import Foundation
import NIO
import NIOConcurrencyHelpers
import SQLServerTDS
import Logging

/// High-level Activity Monitor mirroring SSMS panes via DMV queries.
public final class SQLServerActivityMonitor: @unchecked Sendable {
    private let client: SQLServerClient
    private let waitIgnoreList: Set<String>
    private let baselineLock = NIOLock()
    private let logger = Logger(label: "tds.sqlserver.activity-monitor")

    // Baselines for delta computation across snapshots
    private var lastWaits: [String: SQLServerWaitStat] = [:]
    private var lastFileIO: [String: SQLServerFileIOStat] = [:]
    private var lastBatchRequests: Int64?
    private var lastSnapshotTime: Date?

    /// Tracks consecutive permission-denied errors to stop polling.
    private var permissionDeniedCount: Int = 0

    public init(client: SQLServerClient) {
        self.client = client
        self.waitIgnoreList = [
            "SLEEP_TASK", "BROKER_TASK_STOP", "BROKER_TO_FLUSH", "LAZYWRITER_SLEEP",
            "SLEEP_SYSTEMTASK", "SLEEP_BPOOL_FLUSH", "BROKER_EVENTHANDLER", "XE_TIMER_EVENT",
            "XE_DISPATCHER_JOIN", "BROKER_RECEIVE_WAITFOR", "ONDEMAND_TASK_QUEUE",
            "REQUEST_FOR_DEADLOCK_SEARCH", "LOGMGR_QUEUE", "FT_IFTS_SCHEDULER_IDLE_WAIT",
            "BROKER_TRANSMITTER", "AUDIT_LOG_FLUSH", "DBMIRROR_EVENTS_QUEUE", "BROKER_FORWARDER",
            "SQLTRACE_BUFFER_FLUSH", "CLR_AUTO_EVENT", "CLR_MANUAL_EVENT", "DISPATCHER_QUEUE_SEMAPHORE",
            "HADR_FILESTREAM_IOMGR_IOCOMPLETION", "DIRTY_PAGE_POLL", "XE_DISPATCHER_WAIT"
        ]
    }

    // MARK: - Public API

    /// Takes a single snapshot of activity.
    public func snapshot(options: SQLServerActivityOptions = .init(), on eventLoop: EventLoop? = nil) -> EventLoopFuture<SQLServerActivitySnapshot> {
        let loop = eventLoop ?? client.eventLoopGroup.next()
        
        logger.debug("Activity Monitor: Starting snapshot")

        let permissionDeniedInSnapshot = NIOLockedValueBox(0)

        let overviewFut = fetchOverview(on: loop).recover { [weak self] error in
            if Self.isPermissionDenied(error) {
                permissionDeniedInSnapshot.withLockedValue { $0 += 1 }
            }
            self?.logger.error("Activity Monitor: Failed to fetch overview: \(error)")
            return nil
        }

        let processesFut = fetchProcesses(options: options, on: loop).recover { [weak self] error in
            if Self.isPermissionDenied(error) {
                permissionDeniedInSnapshot.withLockedValue { $0 += 1 }
            }
            self?.logger.error("Activity Monitor: Failed to fetch processes: \(error)")
            return []
        }

        let waitsFut = fetchWaits(on: loop).recover { [weak self] error in
            if Self.isPermissionDenied(error) {
                permissionDeniedInSnapshot.withLockedValue { $0 += 1 }
            }
            self?.logger.error("Activity Monitor: Failed to fetch waits: \(error)")
            return []
        }

        let fileIoFut = fetchFileIO(on: loop).recover { [weak self] error in
            if Self.isPermissionDenied(error) {
                permissionDeniedInSnapshot.withLockedValue { $0 += 1 }
            }
            self?.logger.error("Activity Monitor: Failed to fetch file IO: \(error)")
            return []
        }

        let expensiveFut = fetchExpensiveQueries(options: options, on: loop).recover { [weak self] error in
            if Self.isPermissionDenied(error) {
                permissionDeniedInSnapshot.withLockedValue { $0 += 1 }
            }
            self?.logger.error("Activity Monitor: Failed to fetch expensive queries: \(error)")
            return []
        }

        return overviewFut.and(processesFut).flatMap { overview, procs in
            return waitsFut.and(fileIoFut).flatMap { waits, fileIO in
                return expensiveFut.map { expensive in
                    // Track permission-denied errors across snapshots
                    if permissionDeniedInSnapshot.withLockedValue({ $0 }) >= 4 {
                        self.baselineLock.withLock { self.permissionDeniedCount += 1 }
                        self.logger.warning("Activity Monitor: All DMV queries denied — user lacks VIEW SERVER STATE. Snapshot \(self.permissionDeniedCount) of 2 before stopping.")
                    } else {
                        self.baselineLock.withLock { self.permissionDeniedCount = 0 }
                    }

                    let waitsDelta = self.computeWaitDeltas(current: waits)
                    let fileDelta = self.computeFileIODeltas(current: fileIO)

                    let totalIoBytes = fileDelta.reduce(Int64(0)) { $0 + $1.bytesReadDelta + $1.bytesWrittenDelta }
                    let ioMB = Double(totalIoBytes) / (1024 * 1024)

                    let finalOverview: SQLServerActivityOverview?
                    if let ov = overview {
                        finalOverview = SQLServerActivityOverview(
                            processorTimePercent: ov.processorTimePercent,
                            waitingTasksCount: ov.waitingTasksCount,
                            databaseIOMBPerSec: ioMB,
                            batchRequestsPerSec: ov.batchRequestsPerSec
                        )
                    } else {
                        finalOverview = nil
                    }

                    return SQLServerActivitySnapshot(
                        capturedAt: Date(),
                        overview: finalOverview,
                        processes: procs,
                        waits: waits,
                        waitsDelta: waitsDelta,
                        fileIO: fileIO,
                        fileIODelta: fileDelta,
                        expensiveQueries: expensive
                    )
                }
            }
        }
    }

    /// Whether polling should stop due to repeated permission-denied errors.
    public var isPermissionDenied: Bool {
        baselineLock.withLock { permissionDeniedCount >= 2 }
    }

    @available(macOS 12.0, *)
    public func snapshot(options: SQLServerActivityOptions = .init()) async throws -> SQLServerActivitySnapshot {
        try await withCheckedThrowingContinuation { continuation in
            self.snapshot(options: options).whenComplete { result in
                continuation.resume(with: result)
            }
        }
    }

    /// Kills a session (spid) via KILL <session_id>.
    public func killSession(sessionId: Int, on eventLoop: EventLoop? = nil) -> EventLoopFuture<Void> {
        let sql = "KILL \(sessionId);"
        return client.execute(sql, on: eventLoop).map { _ in () }
    }

    @available(macOS 12.0, *)
    public func killSession(sessionId: Int) async throws {
        _ = try await client.execute("KILL \(sessionId);")
    }

    /// Streams snapshots on a configurable interval (default 5s). Cancels when the consumer drops.
    /// Automatically stops if the user lacks VIEW SERVER STATE after two consecutive failed snapshots.
    @available(macOS 12.0, *)
    public func streamSnapshots(every seconds: TimeInterval = 5.0, options: SQLServerActivityOptions = .init()) -> AsyncThrowingStream<SQLServerActivitySnapshot, Error> {
        AsyncThrowingStream { continuation in
            let task = Task {
                while !Task.isCancelled {
                    do {
                        let snap = try await self.snapshot(options: options)
                        continuation.yield(snap)
                    } catch {
                        logger.error("Activity Monitor: Stream snapshot error: \(error)")
                    }

                    // Stop polling if permission denied on consecutive snapshots
                    if self.isPermissionDenied {
                        self.logger.warning("Activity Monitor: Stopping polling — user lacks required server permissions.")
                        break
                    }

                    try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                }
                continuation.finish()
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    /// Whether the error message indicates a permission-denied failure.
    private static func isPermissionDenied(_ error: Error) -> Bool {
        let msg = "\(error)"
        return msg.contains("permission was denied") || msg.contains("not have permission")
    }

    // MARK: - Queries

    private func fetchOverview(on loop: EventLoop) -> EventLoopFuture<SQLServerActivityOverview?> {
        let cpuSql = """
        SELECT TOP(1) [SQLProcessUtilization] AS cpu_usage
        FROM (
            SELECT record.value('(./Record/SchedulerMonitorEvent/SystemHealth/ProcessUtilization)[1]', 'int') AS [SQLProcessUtilization],
            [timestamp]
            FROM (
                SELECT [timestamp], convert(xml, record) AS [record]
                FROM sys.dm_os_ring_buffers
                WHERE ring_buffer_type = N'RING_BUFFER_SCHEDULER_MONITOR'
                AND record LIKE '%<SchedulerMonitorEvent>%'
            ) AS x
        ) AS y ORDER BY [timestamp] DESC;
        """
        
        let waitIgnoreCSV = waitIgnoreList.map { "'\($0)'" }.joined(separator: ", ")
        let waitsSql = "SELECT COUNT(*) AS waiting_tasks FROM sys.dm_os_waiting_tasks WHERE wait_type NOT IN (\(waitIgnoreCSV));"
        
        let batchSql = "SELECT cntr_value FROM sys.dm_os_performance_counters WHERE counter_name = 'Batch Requests/sec' AND object_name LIKE '%SQL Statistics%';"

        let cpuFut = client.query(cpuSql, on: loop).map { $0.first?.column("cpu_usage")?.int ?? 0 }.recover { _ in 0 }
        let waitsFut = client.query(waitsSql, on: loop).map { $0.first?.column("waiting_tasks")?.int ?? 0 }.recover { _ in 0 }
        let batchFut = client.query(batchSql, on: loop).map { $0.first?.column("cntr_value")?.int64 ?? 0 }.recover { _ in 0 }

        return cpuFut.and(waitsFut).flatMap { cpu, waits in
            return batchFut.map { batchTotal in
                let now = Date()
                var batchRate: Double = 0

                self.baselineLock.withLock {
                    if let lastTime = self.lastSnapshotTime, let lastBatch = self.lastBatchRequests {
                        let elapsed = now.timeIntervalSince(lastTime)
                        if elapsed > 0 {
                            batchRate = Double(max(0, batchTotal - lastBatch)) / elapsed
                        }
                    }
                    self.lastBatchRequests = batchTotal
                    self.lastSnapshotTime = now
                }

                return SQLServerActivityOverview(
                    processorTimePercent: Double(cpu),
                    waitingTasksCount: waits,
                    databaseIOMBPerSec: 0, 
                    batchRequestsPerSec: batchRate
                )
            }
        }
    }

    /// The statement behind the process list. The plan is the biggest part of a row (tens of kilobytes) and nothing
    /// shows it, so it is only read when `options.includeQueryPlan` asks.
    static func processesSQL(options: SQLServerActivityOptions) -> String {
        return """
        SELECT
            s.session_id,
            s.login_name,
            s.host_name,
            s.program_name,
            s.status AS session_status,
            s.cpu_time AS session_cpu_time_ms,
            s.reads AS session_reads,
            s.writes AS session_writes,
            s.memory_usage AS session_memory_pages,
            c.client_net_address,
            r.status AS request_status,
            r.command,
            r.cpu_time AS request_cpu_time_ms,
            r.total_elapsed_time AS request_total_elapsed_ms,
            r.wait_type,
            r.wait_time AS request_wait_time_ms,
            r.last_wait_type,
            r.blocking_session_id,
            r.database_id,
            r.start_time,
            r.percent_complete,
            \(options.includeSqlText ? "st.text" : "CAST(NULL AS NVARCHAR(MAX))") AS sql_text,
            \(options.includeQueryPlan ? "CAST(qp.query_plan AS NVARCHAR(MAX))" : "CAST(NULL AS NVARCHAR(MAX))") AS plan_xml
        FROM sys.dm_exec_sessions AS s
        LEFT JOIN sys.dm_exec_connections AS c ON c.session_id = s.session_id
        LEFT JOIN sys.dm_exec_requests   AS r ON r.session_id = s.session_id
        \(options.includeSqlText ? "OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) AS st" : "")
        \(options.includeQueryPlan ? "OUTER APPLY sys.dm_exec_query_plan(r.plan_handle) AS qp" : "")
        WHERE s.session_id <> @@SPID
        ORDER BY s.session_id;
        """

    }

    private func fetchProcesses(options: SQLServerActivityOptions, on loop: EventLoop) -> EventLoopFuture<[SQLServerProcessInfo]> {
        let sql = Self.processesSQL(options: options)

        return client.query(sql, on: loop).map { rows in
            rows.compactMap { row in
                guard let sid = row.column("session_id")?.int else { return nil }
                let pages = row.column("session_memory_pages")?.int ?? 0
                let memKB = pages * 8 
                let req = SQLServerProcessInfo.Request(
                    status: row.column("request_status")?.string,
                    command: row.column("command")?.string,
                    cpuTimeMs: row.column("request_cpu_time_ms")?.int,
                    totalElapsedMs: row.column("request_total_elapsed_ms")?.int,
                    waitType: row.column("wait_type")?.string,
                    waitTimeMs: row.column("request_wait_time_ms")?.int,
                    lastWaitType: row.column("last_wait_type")?.string,
                    blockingSessionId: row.column("blocking_session_id")?.int,
                    databaseId: row.column("database_id")?.int,
                    startTime: row.column("start_time")?.date,
                    percentComplete: row.column("percent_complete")?.double,
                    sqlText: row.column("sql_text")?.string,
                    planXml: row.column("plan_xml")?.string
                )
                return SQLServerProcessInfo(
                    sessionId: sid,
                    loginName: row.column("login_name")?.string,
                    hostName: row.column("host_name")?.string,
                    programName: row.column("program_name")?.string,
                    clientNetAddress: row.column("client_net_address")?.string,
                    sessionStatus: row.column("session_status")?.string,
                    sessionCpuTimeMs: row.column("session_cpu_time_ms")?.int,
                    sessionReads: row.column("session_reads")?.int,
                    sessionWrites: row.column("session_writes")?.int,
                    memoryUsageKB: memKB,
                    request: row.column("request_status") == nil ? nil : req
                )
            }
        }
    }

    private func fetchWaits(on loop: EventLoop) -> EventLoopFuture<[SQLServerWaitStat]> {
        let waitIgnoreCSV = waitIgnoreList.map { "'\($0)'" }.joined(separator: ", ")
        let sql = """
        SELECT wait_type, waiting_tasks_count, wait_time_ms, signal_wait_time_ms
        FROM sys.dm_os_wait_stats
        WHERE wait_type NOT IN (\(waitIgnoreCSV))
        AND wait_time_ms > 0
        ORDER BY wait_time_ms DESC;
        """
        return client.query(sql, on: loop).map { rows in
            rows.compactMap { row in
                guard let wt = row.column("wait_type")?.string,
                      let tasks = row.column("waiting_tasks_count")?.int,
                      let time = row.column("wait_time_ms")?.int,
                      let signal = row.column("signal_wait_time_ms")?.int
                else { return nil }
                return SQLServerWaitStat(waitType: wt, waitingTasksCount: tasks, waitTimeMs: time, signalWaitTimeMs: signal)
            }
        }
    }

    private func fetchFileIO(on loop: EventLoop) -> EventLoopFuture<[SQLServerFileIOStat]> {
        let sql = """
        SELECT
            vfs.database_id,
            vfs.file_id,
            DB_NAME(vfs.database_id) AS database_name,
            mf.name AS file_name,
            vfs.num_of_reads,
            vfs.num_of_writes,
            vfs.num_of_bytes_read,
            vfs.num_of_bytes_written,
            vfs.io_stall_read_ms,
            vfs.io_stall_write_ms
        FROM sys.dm_io_virtual_file_stats(NULL, NULL) AS vfs
        INNER JOIN sys.master_files AS mf
            ON vfs.database_id = mf.database_id AND vfs.file_id = mf.file_id
        ORDER BY vfs.database_id, vfs.file_id;
        """
        return client.query(sql, on: loop).map { rows in
            rows.compactMap { row in
                guard let dbid = row.column("database_id")?.int, let fid = row.column("file_id")?.int else { return nil }
                return SQLServerFileIOStat(
                    databaseId: dbid,
                    fileId: fid,
                    databaseName: row.column("database_name")?.string,
                    fileName: row.column("file_name")?.string,
                    numReads: row.column("num_of_reads")?.int ?? 0,
                    numWrites: row.column("num_of_writes")?.int ?? 0,
                    bytesRead: Int64(row.column("num_of_bytes_read")?.int64 ?? 0),
                    bytesWritten: Int64(row.column("num_of_bytes_written")?.int64 ?? 0),
                    ioStallReadMs: Int64(row.column("io_stall_read_ms")?.int64 ?? 0),
                    ioStallWriteMs: Int64(row.column("io_stall_write_ms")?.int64 ?? 0)
                )
            }
        }
    }

    /// The statement behind the expensive-queries list: twenty rows, each with its text and, only when
    /// `options.includeQueryPlan` asks, its whole plan (megabytes every refresh).
    static func expensiveQueriesSQL(options: SQLServerActivityOptions) -> String {
        return """
        SELECT TOP (20)
            qs.query_hash,
            qs.execution_count,
            qs.total_worker_time,
            qs.total_elapsed_time,
            qs.total_logical_reads,
            qs.total_logical_writes,
            qs.max_worker_time,
            qs.max_elapsed_time,
            qs.last_execution_time,
            \(options.includeSqlText ? "st.text" : "CAST(NULL AS NVARCHAR(MAX))") AS sql_text,
            \(options.includeQueryPlan ? "CAST(qp.query_plan AS NVARCHAR(MAX))" : "CAST(NULL AS NVARCHAR(MAX))") AS plan_xml,
            DB_NAME(CONVERT(INT, pa.value)) AS database_name
        FROM sys.dm_exec_query_stats AS qs
        \(options.includeSqlText ? "OUTER APPLY sys.dm_exec_sql_text(qs.sql_handle) AS st" : "")
        \(options.includeQueryPlan ? "OUTER APPLY sys.dm_exec_query_plan(qs.plan_handle) AS qp" : "")
        OUTER APPLY (
            SELECT TOP(1) value FROM sys.dm_exec_plan_attributes(qs.plan_handle)
            WHERE attribute = 'dbid'
        ) AS pa
        ORDER BY qs.total_worker_time DESC;
        """

    }

    private func fetchExpensiveQueries(options: SQLServerActivityOptions, on loop: EventLoop) -> EventLoopFuture<[SQLServerExpensiveQuery]> {
        let sql = Self.expensiveQueriesSQL(options: options)

        return client.query(sql, on: loop).map { rows in
            rows.enumerated().map { index, row in
                let hashBytes = row.column("query_hash")?.bytes ?? []
                let hashHex = hashBytes.isEmpty ? nil : ("0x" + hashBytes.map { String(format: "%02X", $0) }.joined())
                return SQLServerExpensiveQuery(
                    id: "\(hashHex ?? "q")-\(index)",
                    queryHashHex: hashHex,
                    executionCount: row.column("execution_count")?.int ?? 0,
                    totalWorkerTime: Int64(row.column("total_worker_time")?.int64 ?? 0),
                    totalElapsedTime: Int64(row.column("total_elapsed_time")?.int64 ?? 0),
                    totalLogicalReads: Int64(row.column("total_logical_reads")?.int64 ?? 0),
                    totalLogicalWrites: Int64(row.column("total_logical_writes")?.int64 ?? 0),
                    maxWorkerTime: Int64(row.column("max_worker_time")?.int64 ?? 0),
                    maxElapsedTime: Int64(row.column("max_elapsed_time")?.int64 ?? 0),
                    lastExecutionTime: row.column("last_execution_time")?.date,
                    sqlText: row.column("sql_text")?.string,
                    planXml: row.column("plan_xml")?.string,
                    databaseName: row.column("database_name")?.string
                )
            }
        }
    }

    // MARK: - Delta helpers

    private func computeWaitDeltas(current: [SQLServerWaitStat]) -> [SQLServerWaitStatDelta] {
        var deltas: [SQLServerWaitStatDelta] = []
        let previous = baselineLock.withLock { lastWaits }
        for w in current {
            if let prev = previous[w.waitType] {
                let d = SQLServerWaitStatDelta(
                    waitType: w.waitType,
                    waitingTasksCountDelta: max(0, w.waitingTasksCount - prev.waitingTasksCount),
                    waitTimeMsDelta: max(0, w.waitTimeMs - prev.waitTimeMs),
                    signalWaitTimeMsDelta: max(0, w.signalWaitTimeMs - prev.signalWaitTimeMs)
                )
                if d.waitTimeMsDelta > 0 || d.waitingTasksCountDelta > 0 {
                    deltas.append(d)
                }
            }
        }
        // update baseline
        baselineLock.withLock {
            lastWaits = Dictionary(uniqueKeysWithValues: current.map { ($0.waitType, $0) })
        }
        return deltas.sorted { $0.waitTimeMsDelta > $1.waitTimeMsDelta }
    }

    private func computeFileIODeltas(current: [SQLServerFileIOStat]) -> [SQLServerFileIOStatDelta] {
        func key(_ s: SQLServerFileIOStat) -> String { "\(s.databaseId):\(s.fileId)" }
        var deltas: [SQLServerFileIOStatDelta] = []
        let previous = baselineLock.withLock { lastFileIO }
        for f in current {
            let k = key(f)
            if let prev = previous[k] {
                let d = SQLServerFileIOStatDelta(
                    databaseId: f.databaseId,
                    fileId: f.fileId,
                    databaseName: f.databaseName,
                    fileName: f.fileName,
                    numReadsDelta: max(0, f.numReads - prev.numReads),
                    numWritesDelta: max(0, f.numWrites - prev.numWrites),
                    bytesReadDelta: max(0, f.bytesRead - prev.bytesRead),
                    bytesWrittenDelta: max(0, f.bytesWritten - prev.bytesWritten),
                    ioStallReadMsDelta: max(0, f.ioStallReadMs - prev.ioStallReadMs),
                    ioStallWriteMsDelta: max(0, f.ioStallWriteMs - prev.ioStallWriteMs)
                )
                deltas.append(d)
            }
        }
        // update baseline
        baselineLock.withLock {
            lastFileIO = Dictionary(uniqueKeysWithValues: current.map { (key($0), $0) } )
        }
        return deltas
    }
}
