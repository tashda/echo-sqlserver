import Foundation
import Logging
import NIO
import NIOConcurrencyHelpers
import SQLServerTDS

public final class SQLServerClient: @unchecked Sendable {
    internal enum EventLoopGroupProvider {
        case shared(EventLoopGroup)
        case createNew(numberOfThreads: Int)
    }

    public let configuration: Configuration
    internal let eventLoopGroup: EventLoopGroup
    internal private(set) var ownsEventLoopGroup: Bool
    internal let pool: SQLServerConnectionPool
    public let logger: Logger
    internal let retryConfiguration: SQLServerRetryConfiguration
    internal let metadataCache: MetadataCache<[ColumnMetadata]>?

    internal let stateLock = NIOLock()
    internal var _isShutdown = false
    internal var inFlightOperations: Int = 0
    internal var drainWaiters: [EventLoopPromise<Void>] = []

    /// The event loops every client made without a thread count shares. A loop thread serves any number of connections, so a
    /// client per server (or per database) must not start a group of threads of its own: four connections to as many servers
    /// took the app from 8 to 42 threads. Never shut down; a client that uses it does not own it.
    internal static let sharedEventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: min(System.coreCount, 4))

    public static func connect(
        configuration: Configuration,
        logger: Logger = Logger(label: "tds.sqlserver.client")
    ) async throws -> SQLServerClient {
        do {
            return try await connect(
                configuration: configuration,
                eventLoopGroupProvider: .shared(sharedEventLoopGroup),
                logger: logger
            ).get()
        } catch {
            throw SQLServerError.normalize(error)
        }
    }

    public static func connect(
        configuration: Configuration,
        numberOfThreads: Int,
        logger: Logger = Logger(label: "tds.sqlserver.client")
    ) async throws -> SQLServerClient {
        let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: numberOfThreads)
        do {
            // Use .shared so the ELF connect does NOT own or shut down the ELG on error.
            // We manage the ELG lifecycle here in async code instead.
            let client = try await connect(
                configuration: configuration,
                eventLoopGroupProvider: .shared(eventLoopGroup),
                logger: logger
            ).get()
            // Transfer ELG ownership to the client so it shuts down the group on close.
            client.transferEventLoopGroupOwnership(eventLoopGroup)
            return client
        } catch {
            // Clean up the ELG using pure async — no ELF hopping race.
            try? await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                eventLoopGroup.shutdownGracefully { shutdownError in
                    if let shutdownError {
                        continuation.resume(throwing: shutdownError)
                    } else {
                        continuation.resume()
                    }
                }
            }
            throw SQLServerError.normalize(error)
        }
    }

    public static func connect(
        hostname: String,
        port: Int = 1433,
        database: String = "master",
        authentication: SQLServerAuthentication,
        tlsEnabled: Bool = true,
        trustServerCertificate: Bool = false,
        caCertificatePath: String? = nil,
        encryptionMode: SQLServerEncryptionMode = .mandatory,
        numberOfThreads: Int = min(System.coreCount, 4),
        poolConfiguration: SQLServerConnectionPool.Configuration = .init(),
        metadataConfiguration: SQLServerMetadataOperations.Configuration = .init(),
        retryConfiguration: SQLServerRetryConfiguration = .init(),
        transparentNetworkIPResolution: Bool = true,
        logger: Logger = Logger(label: "tds.sqlserver.client")
    ) async throws -> SQLServerClient {
        try await connect(
            configuration: .init(
                hostname: hostname,
                port: port,
                database: database,
                authentication: authentication,
                tlsEnabled: tlsEnabled,
                trustServerCertificate: trustServerCertificate,
                caCertificatePath: caCertificatePath,
                encryptionMode: encryptionMode,
                poolConfiguration: poolConfiguration,
                metadataConfiguration: metadataConfiguration,
                retryConfiguration: retryConfiguration,
                transparentNetworkIPResolution: transparentNetworkIPResolution
            ),
            numberOfThreads: numberOfThreads,
            logger: logger
        )
    }

    internal static func connect(
        configuration: Configuration,
        eventLoopGroupProvider: EventLoopGroupProvider = .createNew(numberOfThreads: min(System.coreCount, 4)),
        logger: Logger = Logger(label: "tds.sqlserver.client")
    ) -> EventLoopFuture<SQLServerClient> {
        let eventLoopGroup: EventLoopGroup
        let ownsGroup: Bool

        switch eventLoopGroupProvider {
        case .shared(let group):
            eventLoopGroup = group
            ownsGroup = false
        case .createNew(let numberOfThreads):
            eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: numberOfThreads)
            ownsGroup = true
        }


        let connectionFactory: (EventLoop) -> EventLoopFuture<TDSConnection> = { eventLoop in
            SQLServerConnection.openSession(configuration: configuration.connection, on: eventLoop, logger: logger)
        }

        let resetBatch = configuration.connection.sessionResetBatch
        let pool = SQLServerConnectionPool(
            configuration: configuration.poolConfiguration,
            eventLoopGroup: eventLoopGroup,
            logger: logger,
            connectionFactory: connectionFactory,
            sessionReset: { connection in
                SQLServerConnection.runSessionBatch(resetBatch, on: connection, resetConnection: true, timeout: .seconds(15))
            }
        )

        let loop = eventLoopGroup.next()
        // Opening one session up front surfaces configuration and credential
        // errors from connect(). The session then serves the first checkout.
        return connectionFactory(loop).map { connection in
            pool.adoptIdle(connection)
            pool.start()
            return SQLServerClient(
                configuration: configuration,
                eventLoopGroup: eventLoopGroup,
                ownsEventLoopGroup: ownsGroup,
                pool: pool,
                logger: logger
            )
        }.flatMapError { error in
            pool.shutdownGracefully().flatMapThrowing { _ -> SQLServerClient in
                // Fire-and-forget ELG shutdown — returning a future from shutdownEventLoopGroup
                // would require NIO to hop back to this event loop which is being shut down.
                if ownsGroup {
                    eventLoopGroup.shutdownGracefully { _ in }
                }
                throw SQLServerError.normalize(error)
            }
        }
    }

    public func shutdownGracefully() async throws {
        try await shutdownGracefully(drainTimeout: 10)
    }

    /// Stops accepting operations, waits up to `drainTimeout` seconds for
    /// running operations to finish, then closes every session. Operations
    /// still running at that point fail with `connectionClosed`, so shutdown
    /// cannot hang behind a long-running query.
    public func shutdownGracefully(drainTimeout: TimeInterval) async throws {
        var already = false
        stateLock.withLock {
            if _isShutdown { already = true } else { _isShutdown = true }
        }
        if already { return }

        // Wait for in-flight operations (including connection close/invalidate)
        // using the drain waiter pattern instead of busy-polling.
        let needsDrain: Bool = stateLock.withLock { inFlightOperations > 0 }
        if needsDrain {
            let loop = eventLoopGroup.next()
            let force = loop.scheduleTask(in: drainTimeout.nioTimeAmount) { [pool, logger] in
                logger.warning("Operations still running after \(drainTimeout)s; closing their connections")
                _ = pool.shutdownGracefully()
            }
            defer { force.cancel() }
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                let p = loop.makePromise(of: Void.self)
                self.stateLock.withLock { self.drainWaiters.append(p) }
                p.futureResult.whenComplete { result in
                    switch result {
                    case .success: continuation.resume()
                    case .failure(let error): continuation.resume(throwing: error)
                    }
                }
                // Re-check: operations may have completed between our check and
                // adding the waiter, so drain immediately if already at zero.
                let stillPending: Bool = self.stateLock.withLock { self.inFlightOperations > 0 }
                if !stillPending {
                    var toComplete: [EventLoopPromise<Void>] = []
                    self.stateLock.withLock {
                        toComplete = self.drainWaiters
                        self.drainWaiters.removeAll(keepingCapacity: false)
                    }
                    toComplete.forEach { $0.succeed(()) }
                }
            }
        }

        try await pool.shutdownGracefully().get()

        if ownsEventLoopGroup {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                eventLoopGroup.shutdownGracefully { error in
                    if let error {
                        continuation.resume(throwing: error)
                    } else {
                        continuation.resume()
                    }
                }
            }
        }
    }

    public func close() async throws {
        try await shutdownGracefully()
    }

    @available(macOS 12.0, *)
    public func connection() async throws -> SQLServerConnection {
        try await acquireHealthyConnection(on: eventLoopGroup.next()).get()
    }

    internal func shutdownGracefully() -> EventLoopFuture<Void> {
        let loop = eventLoopGroup.next()
        var already = false
        stateLock.withLock {
            if _isShutdown { already = true } else { _isShutdown = true }
        }
        if already { return loop.makeSucceededFuture(()) }
        let drained: EventLoopFuture<Void>
        if inFlightOperations == 0 {
            drained = loop.makeSucceededFuture(())
        } else {
            let p = loop.makePromise(of: Void.self)
            stateLock.withLock { drainWaiters.append(p) }
            drained = p.futureResult
        }
        return drained.flatMap { self.pool.shutdownGracefully() }.map { _ in
            // Fire-and-forget the ELG shutdown. We cannot return a future that depends on
            // the ELG shutdown completing, because NIO would need to hop the result back to
            // this event loop — which is the one being shut down — causing a race.
            if self.ownsEventLoopGroup {
                self.eventLoopGroup.shutdownGracefully { _ in }
            }
        }
    }

    internal func beginOperation() -> Bool {
        stateLock.withLock { () -> Bool in
            guard !_isShutdown else { return false }
            inFlightOperations += 1
            return true
        }
    }

    internal func endOperation() {
        var toComplete: [EventLoopPromise<Void>] = []
        stateLock.withLock {
            inFlightOperations = max(0, inFlightOperations - 1)
            if inFlightOperations == 0 && _isShutdown {
                toComplete = drainWaiters
                drainWaiters.removeAll(keepingCapacity: false)
            }
        }
        toComplete.forEach { $0.succeed(()) }
    }

    public func withConnection<Result: Sendable>(
        on eventLoop: EventLoop? = nil,
        _ operation: @Sendable @escaping (SQLServerConnection) -> EventLoopFuture<Result>
    ) -> EventLoopFuture<Result> {
        if let scoped = ClientScopedConnection.current {
            return operation(scoped)
        }
        let loop = eventLoop ?? eventLoopGroup.next()
        let accepted = self.stateLock.withLock { () -> Bool in
            guard !self._isShutdown else { return false }
            self.inFlightOperations += 1
            return true
        }
        guard accepted else { return loop.makeFailedFuture(SQLServerError.clientShutdown) }
        let fut = self.acquireHealthyConnection(on: loop).flatMap { sqlConnection -> EventLoopFuture<Result> in
                // Track the FULL withConnection lifecycle (including connection
                // close/invalidate) so shutdownGracefully() cannot proceed while
                // connections are still being returned to the pool.
                let op = operation(sqlConnection)
                return op.flatMap { value in
                    sqlConnection.close().map { value }
                }.flatMapError { error in
                    let normalized = SQLServerError.normalize(error)
                    // A usable session goes back to the pool, which resets it
                    // before reuse; a broken one is discarded.
                    let returned = normalized.isConnectionLost || sqlConnection.underlying.isClosed
                        ? sqlConnection.invalidate()
                        : sqlConnection.close()
                    return returned.recover { _ in () }.flatMapThrowing { _ in throw error }
                }
        }
        return fut.always { _ in
            var toComplete: [EventLoopPromise<Void>] = []
            self.stateLock.withLock {
                self.inFlightOperations = max(0, self.inFlightOperations - 1)
                if self.inFlightOperations == 0 && self._isShutdown {
                    toComplete = self.drainWaiters
                    self.drainWaiters.removeAll(keepingCapacity: false)
                }
            }
            toComplete.forEach { $0.succeed(()) }
        }.withTestTimeoutIfEnabled(on: loop)
    }

    internal init(
        configuration: Configuration,
        eventLoopGroup: EventLoopGroup,
        ownsEventLoopGroup: Bool,
        pool: SQLServerConnectionPool,
        logger: Logger
    ) {
        self.configuration = configuration
        self.eventLoopGroup = eventLoopGroup
        self.ownsEventLoopGroup = ownsEventLoopGroup
        self.pool = pool
        self.logger = logger
        self.retryConfiguration = configuration.retryConfiguration
        if configuration.metadataConfiguration.enableColumnCache {
            self.metadataCache = MetadataCache<[ColumnMetadata]>()
        } else {
            self.metadataCache = nil
        }
    }

    internal func transferEventLoopGroupOwnership(_ group: EventLoopGroup) {
        assert(!ownsEventLoopGroup, "Client already owns an EventLoopGroup")
        assert(group === eventLoopGroup, "Transferred group must match the client's group")
        ownsEventLoopGroup = true
    }

    internal var isClientShutdown: Bool {
        stateLock.withLock { _isShutdown }
    }

    deinit {
        let shut = stateLock.withLock { _isShutdown }
        if !shut {
            logger.warning("SQLServerClient deinitialized without shutdownGracefully()")
        }
    }
}

// Task-local scoped connection used to force nested client operations to reuse the
// same SQLServerConnection (including its current database) within a logical block.
public enum ClientScopedConnection {
    @TaskLocal public static var current: SQLServerConnection?
}
