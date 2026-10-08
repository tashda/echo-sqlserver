import Foundation
import Logging
import NIO
import NIOConcurrencyHelpers
import SQLServerTDS
import NIOSSL

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

extension SQLServerConnection.Configuration {
    /// The batch that establishes the configured session state. It runs after
    /// login and again, together with RESETCONNECTION, before a pooled
    /// session is reused.
    internal var sessionBootstrapBatch: String {
        sessionOptions.buildStatements().joined(separator: " ")
    }

    /// The batch sent with RESETCONNECTION when a pooled session is returned.
    /// The reset restores the login-time state; this re-applies the
    /// configured options, database and default isolation level.
    internal var sessionResetBatch: String {
        var statements = [
            "USE \(SQLServerSQL.escapeIdentifier(login.database));",
            "SET TRANSACTION ISOLATION LEVEL READ COMMITTED;",
        ]
        statements.append(contentsOf: sessionOptions.buildStatements())
        return statements.joined(separator: " ")
    }
}

extension SQLServerConnection.Configuration {
    /// The TLS settings used on the wire.
    ///
    /// With `.optional` and no TLS configuration the session is still fully
    /// encrypted, but the server certificate is not validated. This matches
    /// the Microsoft ODBC 18 and JDBC meaning of Encrypt=Optional (which
    /// encrypts the login without validating the certificate) while also
    /// protecting everything after the login. `.mandatory` and `.strict`
    /// require an explicit configuration.
    internal var effectiveTLSConfiguration: SQLServerTLSConfiguration? {
        var configuration: SQLServerTLSConfiguration
        if let tlsConfiguration {
            configuration = tlsConfiguration
        } else if encryptionMode == .optional {
            configuration = .trustingServerCertificate
        } else {
            return nil
        }
        if allowLegacyTLS, encryptionMode != .strict {
            configuration.minimumTLSVersion = .tlsv1
        }
        return configuration
    }
}

extension SQLServerConnection {
    /// Maximum number of login redirections (ENVCHANGE routing) followed for
    /// one connection attempt.
    static let maximumRoutingRedirects = 2

    /// Opens an authenticated, bootstrapped TDS session, retrying transient
    /// network failures according to `retryConfiguration`. Only connection
    /// establishment is retried; no caller SQL has run at this point.
    internal static func openSession(
        configuration: Configuration,
        on eventLoop: EventLoop,
        logger: Logger,
        attempt: Int = 1
    ) -> EventLoopFuture<TDSConnection> {
        openSessionOnce(configuration: configuration, on: eventLoop, logger: logger).flatMapError { error in
            let normalized = SQLServerError.normalize(error)
            let retry = configuration.retryConfiguration
            guard attempt < retry.maximumAttempts, isRetryableConnectFailure(normalized), retry.shouldRetry(normalized) else {
                return eventLoop.makeFailedFuture(normalized)
            }
            let proposed = retry.backoffStrategy(attempt)
            let delay = proposed.isFinite ? min(max(proposed, 0), 30) : 30
            logger.debug("Connection attempt \(attempt) failed (\(normalized)); retrying in \(delay)s")
            return eventLoop.scheduleTask(in: delay.nioTimeAmount) {}.futureResult.flatMap {
                openSession(configuration: configuration, on: eventLoop, logger: logger, attempt: attempt + 1)
            }
        }
    }

    /// Authentication and TLS failures are deterministic; retrying them only
    /// adds failed logins, which can lock accounts.
    internal static func isRetryableConnectFailure(_ error: SQLServerError) -> Bool {
        switch error {
        case .connectionClosed, .transient, .timeout:
            return true
        case .sqlExecutionError, .deadlockDetected:
            return error.isTransient
        default:
            return false
        }
    }

    /// One connection attempt bounded by `connectTimeoutSeconds`, which covers
    /// DNS, TCP, TLS, login, routing and session bootstrap.
    private static func openSessionOnce(
        configuration cfg: Configuration,
        on eventLoop: EventLoop,
        logger: Logger
    ) -> EventLoopFuture<TDSConnection> {
        guard cfg.effectiveTLSConfiguration != nil else {
            return eventLoop.makeFailedFuture(SQLServerError.invalidArgument(
                "Encryption mode '\(cfg.encryptionMode.rawValue)' requires a TLS configuration. Credentials are never sent unencrypted; use .optional to encrypt without certificate validation."
            ))
        }
        let promise = eventLoop.makePromise(of: TDSConnection.self)
        let pending = NIOLockedValueBox<TDSConnection?>(nil)
        let completed = NIOLockedValueBox(false)
        let seconds = max(1, cfg.connectTimeoutSeconds)
        // Where the attempt is, for the message when the time runs out.
        let stage = NIOLockedValueBox("resolving \(cfg.hostname)")

        func finish(_ result: Result<TDSConnection, Error>) {
            let first = completed.withLockedValue { done -> Bool in
                guard !done else { return false }
                done = true
                return true
            }
            guard first else {
                if case .success(let late) = result { late.closeSilently() }
                return
            }
            promise.completeWith(result)
        }

        let deadline = eventLoop.scheduleTask(in: .seconds(Int64(seconds))) {
            finish(.failure(SQLServerError.timeout(
                description: "login to \(cfg.hostname):\(cfg.port) did not complete within \(seconds)s (\(stage.withLockedValue { $0 }))",
                underlying: nil
            )))
            pending.withLockedValue { $0 }?.closeSilently()
        }

        func connect(host: String, port: Int, redirects: Int) -> EventLoopFuture<TDSConnection> {
            stage.withLockedValue { $0 = "resolving \(host)" }
            return resolveSocketAddresses(hostname: host, port: port, transparentResolution: cfg.transparentNetworkIPResolution, on: eventLoop)
                .flatMap { addresses in
                    stage.withLockedValue { $0 = "\(host) resolved to \(addresses.map(SQLServerAddressRace.describe).joined(separator: ", ")); connecting" }
                    return establishTDSConnection(
                        addresses: addresses,
                        tlsConfiguration: cfg.effectiveTLSConfiguration,
                        serverHostname: redirects == 0 ? (cfg.hostNameInCertificate ?? host) : host,
                        encryptionMode: cfg.encryptionMode.asTDSMode,
                        connectTimeout: .seconds(Int64(seconds)),
                        parallel: cfg.transparentNetworkIPResolution,
                        progress: { text in stage.withLockedValue { $0 = "\(host) resolved to several addresses; \(text)" } },
                        on: eventLoop,
                        logger: logger
                    )
                }
                .flatMap { connection in
                    pending.withLockedValue { $0 = connection }
                    stage.withLockedValue { $0 = "connected and encrypted; waiting for \(host) to answer the sign-in (Windows or SQL login)" }
                    let login = TDSLoginConfiguration(
                        serverName: host,
                        port: port,
                        database: cfg.login.database,
                        authentication: cfg.login.authentication.tdsAuthentication,
                        readOnlyIntent: cfg.readOnlyIntent,
                        applicationName: cfg.applicationName,
                        packetSize: cfg.packetSize,
                        // A redirect names another server, whose SPN follows from its name.
                        serverSPN: redirects == 0 ? cfg.serverSPN : nil,
                        columnEncryption: cfg.columnEncryption
                    )
                    return connection.login(configuration: login)
                        .flatMap { () -> EventLoopFuture<TDSConnection> in
                            guard let target = connection.routingTarget else {
                                return eventLoop.makeSucceededFuture(connection)
                            }
                            // Azure SQL gateways and read-only routing name the
                            // server that must serve this session.
                            return connection.close().recover { _ in }.flatMap {
                                guard redirects < maximumRoutingRedirects else {
                                    return eventLoop.makeFailedFuture(SQLServerError.protocolError(
                                        .protocolError("Server redirected the login more than \(maximumRoutingRedirects) times")
                                    ))
                                }
                                logger.info("Login redirected to \(target.server):\(target.port)")
                                return connect(host: target.server, port: target.port, redirects: redirects + 1)
                            }
                        }
                        .flatMapError { error in
                            connection.close().recover { _ in }.flatMapThrowing { throw SQLServerError.normalize(error) }
                        }
                }
        }

        connect(host: cfg.hostname, port: cfg.port, redirects: 0)
            .flatMapError { error -> EventLoopFuture<TDSConnection> in
                // A certificate that failed verification is fetched again
                // without verifying it, so the error can say what is wrong.
                let normalized = SQLServerError.normalize(error)
                guard case .tlsFailed(let failure) = normalized, failure.isCertificateProblem else {
                    return eventLoop.makeFailedFuture(normalized)
                }
                return diagnoseCertificate(failure, configuration: cfg, on: eventLoop, logger: logger)
                    .flatMapThrowing { throw SQLServerError.tlsFailed($0) }
            }
            .flatMap { connection -> EventLoopFuture<TDSConnection> in
                pending.withLockedValue { $0 = connection }
                let batch = cfg.sessionBootstrapBatch
                guard !batch.isEmpty else { return eventLoop.makeSucceededFuture(connection) }
                stage.withLockedValue { $0 = "signed in; setting up the session" }
                return runSessionBatch(batch, on: connection).map { connection }.flatMapError { error in
                    connection.close().recover { _ in }.flatMapThrowing { throw SQLServerError.normalize(error) }
                }
            }
            .whenComplete { result in
                deadline.cancel()
                finish(result)
            }

        return promise.futureResult
    }

    /// Explains a certificate failure: connects once more without verifying
    /// (stopping after TLS, so no credentials are sent), reads the
    /// certificate and names the first check it fails.
    internal static func diagnoseCertificate(
        _ failure: SQLServerTLSFailure,
        configuration cfg: Configuration,
        on eventLoop: EventLoop,
        logger: Logger
    ) -> EventLoopFuture<SQLServerTLSFailure> {
        let expectedHost = cfg.hostNameInCertificate ?? cfg.hostname
        guard let tls = cfg.effectiveTLSConfiguration else {
            return eventLoop.makeSucceededFuture(failure)
        }
        return resolveSocketAddresses(hostname: cfg.hostname, port: cfg.port, transparentResolution: true, on: eventLoop)
            .flatMap { addresses -> EventLoopFuture<TDSConnection> in
                guard let address = addresses.first else {
                    return eventLoop.makeFailedFuture(SQLServerError.connectionClosed)
                }
                return TDSConnection.connectForCertificateDiagnosis(
                    to: address,
                    tlsConfiguration: tls,
                    serverHostname: expectedHost,
                    encryptionMode: cfg.encryptionMode.asTDSMode,
                    connectTimeout: .seconds(Int64(max(1, cfg.connectTimeoutSeconds))),
                    on: eventLoop,
                    logger: logger
                )
            }
            .flatMap { connection in
                connection.peerCertificate().flatMap { certificate in
                    connection.close().recover { _ in }.map { certificate }
                }
            }
            .map { certificate -> SQLServerTLSFailure in
                guard let certificate else { return failure }
                return classify(certificate, expectedHost: expectedHost, fallback: failure)
            }
            .recover { _ in failure }
    }

    internal static func classify(
        _ certificate: NIOSSLCertificate,
        expectedHost: String,
        fallback: SQLServerTLSFailure,
        now: Date = Date()
    ) -> SQLServerTLSFailure {
        let description = TDSCertificateIdentity.describe(certificate)
        let summary = SQLServerCertificateSummary(
            subject: description.subject,
            issuer: description.issuer,
            names: description.names,
            notValidBefore: description.notValidBefore,
            notValidAfter: description.notValidAfter,
            isSelfSigned: description.isSelfSigned,
            sha256Fingerprint: description.sha256Fingerprint
        )
        let names = summary.names.joined(separator: ", ")
        let dateFormatter = ISO8601DateFormatter()
        dateFormatter.formatOptions = [.withFullDate]
        let kind: SQLServerTLSFailure.Kind
        let message: String
        let nameMatches = TDSCertificateIdentity.matches(certificate, expectedHost: expectedHost)
        let nameNote = nameMatches ? "" : " It is also issued for \(names), not '\(expectedHost)'."
        if fallback.kind == .certificateNameMismatch {
            // The chain was accepted; only the name is wrong.
            kind = .certificateNameMismatch
            message = "The server certificate is for \(names), not '\(expectedHost)'. Connect using one of those names, or set Host Name In Certificate."
        } else if summary.notValidAfter < now {
            kind = .certificateExpired
            message = "The server certificate for \(names) expired on \(dateFormatter.string(from: summary.notValidAfter))."
        } else if summary.notValidBefore > now {
            kind = .certificateNotYetValid
            message = "The server certificate for \(names) is not valid until \(dateFormatter.string(from: summary.notValidBefore)). Check this Mac's clock."
        } else if summary.isSelfSigned {
            kind = .certificateSelfSigned
            message = "The server uses a self-signed certificate (\(summary.subject)), which this Mac does not trust. Trust the certificate or install it as a trusted root.\(nameNote)"
        } else {
            kind = .certificateUntrusted
            message = "The server certificate for \(names) was issued by '\(summary.issuer)', which this Mac does not trust. Trust the certificate or provide the CA certificate.\(nameNote)"
        }
        return SQLServerTLSFailure(kind: kind, message: message, expectedHost: expectedHost, certificate: summary)
    }

    /// Runs a session-control batch and fails if the server reports an error.
    internal static func runSessionBatch(
        _ sql: String,
        on connection: TDSConnection,
        resetConnection: Bool = false,
        timeout: TimeAmount? = nil
    ) -> EventLoopFuture<Void> {
        let messages = NIOLockedValueBox<[SQLServerStreamMessage]>([])
        let request = RawSqlRequest(sql: sql, onMessage: { token, isError in
            messages.withLockedValue { $0.append(SQLServerStreamMessage(token: token, isError: isError)) }
        })
        request.resetConnection = resetConnection
        return connection.start(request, timeout: timeout).future.flatMapThrowing {
            if let error = SQLServerError.fromServerMessages(messages.withLockedValue { $0 }) {
                throw error
            }
        }
    }

    /// Resolves every address of `hostname`. Trying each address in turn lets
    /// a connection succeed when the first address (for example an IPv6
    /// address without a route, or a failed availability-group subnet) is
    /// unreachable.
    internal static func resolveSocketAddresses(
        hostname: String,
        port: Int,
        transparentResolution: Bool,
        on eventLoop: EventLoop
    ) -> EventLoopFuture<[SocketAddress]> {
        if let literal = try? SocketAddress(ipAddress: hostname, port: port) {
            return eventLoop.makeSucceededFuture([literal])
        }
        let promise = eventLoop.makePromise(of: [SocketAddress].self)
        DispatchQueue.global().async {
            do {
                promise.succeed(try getAddresses(hostname: hostname, port: port))
            } catch {
                promise.fail(error)
            }
        }
        return promise.futureResult
    }

    private static func getAddresses(hostname: String, port: Int) throws -> [SocketAddress] {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        #if canImport(Darwin)
        hints.ai_socktype = SOCK_STREAM
        #else
        hints.ai_socktype = Int32(SOCK_STREAM.rawValue)
        #endif
        hints.ai_protocol = Int32(IPPROTO_TCP)
        var result: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(hostname, String(port), &hints, &result)
        guard status == 0, let first = result else {
            let reason = String(cString: gai_strerror(status))
            throw SQLServerError.transient(SQLServerAddressResolutionError(hostname: hostname, reason: reason))
        }
        defer { freeaddrinfo(first) }

        var ipv4: [SocketAddress] = []
        var ipv6: [SocketAddress] = []
        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let info = cursor {
            if let sockaddr = info.pointee.ai_addr {
                switch info.pointee.ai_family {
                case AF_INET:
                    let address = sockaddr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                    ipv4.append(SocketAddress(address, host: hostname))
                case AF_INET6:
                    let address = sockaddr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
                    ipv6.append(SocketAddress(address, host: hostname))
                default:
                    break
                }
            }
            cursor = info.pointee.ai_next
        }
        // SQL Server listeners are most commonly reachable over IPv4; try
        // those first, as the Microsoft drivers do by default.
        var seen = Set<String>()
        let ordered = (ipv4 + ipv6).filter { seen.insert($0.description).inserted }
        guard !ordered.isEmpty else {
            throw SQLServerError.transient(SQLServerAddressResolutionError(hostname: hostname, reason: "no IPv4 or IPv6 address"))
        }
        return ordered
    }

    /// Opens a TDS connection to the first of `addresses` that answers.
    /// With `parallel` (TransparentNetworkIPResolution, on by default) the
    /// addresses are raced; without it they are tried one after the other,
    /// each given the whole `connectTimeout`.
    internal static func establishTDSConnection(
        addresses: [SocketAddress],
        tlsConfiguration: TLSConfiguration?,
        serverHostname: String?,
        encryptionMode: TDSEncryptionMode = .mandatory,
        connectTimeout: TimeAmount,
        parallel: Bool = true,
        progress: @escaping @Sendable (String) -> Void = { _ in },
        on eventLoop: EventLoop,
        logger: Logger
    ) -> EventLoopFuture<TDSConnection> {
        @Sendable
        func connect(to address: SocketAddress) -> EventLoopFuture<TDSConnection> {
            TDSConnection.connect(
                to: address,
                tlsConfiguration: tlsConfiguration,
                serverHostname: serverHostname,
                encryptionMode: encryptionMode,
                connectTimeout: connectTimeout,
                on: eventLoop,
                logger: logger
            )
        }
        // Only a failure to reach the address moves on to the next one.
        // TLS or protocol failures come from the server itself.
        @Sendable
        func isUnreachable(_ error: Error) -> Bool {
            if case .transient = SQLServerError.normalize(error) { return true }
            return false
        }

        if parallel, addresses.count > 1 {
            return SQLServerAddressRace.run(
                addresses: addresses,
                on: eventLoop,
                attempt: connect(to:),
                discard: { $0.closeSilently() },
                isUnreachable: isUnreachable,
                progress: progress
            )
        }

        @Sendable
        func attempt(_ remaining: ArraySlice<SocketAddress>, lastError: Error?) -> EventLoopFuture<TDSConnection> {
            guard let next = remaining.first else {
                return eventLoop.makeFailedFuture(lastError ?? SQLServerError.connectionClosed)
            }
            progress("connecting: no answer yet from \(SQLServerAddressRace.describe(next))")
            return connect(to: next).flatMapError { error in
                guard remaining.count > 1, isUnreachable(error) else {
                    return eventLoop.makeFailedFuture(error)
                }
                logger.debug("Could not reach \(next); trying next address")
                return attempt(remaining.dropFirst(), lastError: error)
            }
        }
        return attempt(addresses[...], lastError: nil)
    }
}

public struct SQLServerAddressResolutionError: Error, CustomStringConvertible, Sendable {
    public let hostname: String
    public let reason: String

    public var description: String {
        "Could not resolve hostname '\(hostname)': \(reason)"
    }
}
