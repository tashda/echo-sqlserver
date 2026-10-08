import Foundation
import NIO
import NIOConcurrencyHelpers

/// Connects to a host that has several addresses the way SSMS and the
/// Microsoft drivers do (MultiSubnetFailover / TransparentNetworkIPResolution):
/// the first address gets a short head start, then each further address is
/// tried alongside it, and the first to answer wins. A host whose first address
/// is not routable from this machine (a second network card, a cluster
/// address, an IPv6 record without a route) then connects as fast as its
/// reachable address, instead of waiting out the timeout on the dead one.
internal enum SQLServerAddressRace {
    /// How long an address is given before the next one is started alongside it.
    static let defaultStagger: TimeAmount = .milliseconds(500)

    private enum Next { case ignore, fail, launch }

    private struct State {
        var finished = false
        var launched = 0
        var pending: [String] = []
        var failed: [String] = []
        var timers: [Scheduled<Void>] = []
    }

    /// The address as people write it: `10.0.0.5:1433`, `[fe80::1]:1433`.
    static func describe(_ address: SocketAddress) -> String {
        guard let ip = address.ipAddress, let port = address.port else { return address.description }
        return address.protocol == .inet6 ? "[\(ip)]:\(port)" : "\(ip):\(port)"
    }

    /// Starts `attempt` for the first address now and for each following
    /// address after `stagger` (or at once when an earlier one fails to be
    /// reached). Completes with the first success; the others that succeed
    /// later are handed to `discard`. Fails when every address failed, or at
    /// once when an address fails for a reason other than being unreachable
    /// (`isUnreachable` is false): that answer came from the server itself.
    ///
    /// `progress` receives a sentence naming the addresses still waiting and
    /// those that failed, on every change, for the timeout message.
    static func run<Connection: Sendable>(
        addresses: [SocketAddress],
        stagger: TimeAmount = defaultStagger,
        on eventLoop: EventLoop,
        attempt: @escaping @Sendable (SocketAddress) -> EventLoopFuture<Connection>,
        discard: @escaping @Sendable (Connection) -> Void,
        isUnreachable: @escaping @Sendable (Error) -> Bool,
        progress: @escaping @Sendable (String) -> Void
    ) -> EventLoopFuture<Connection> {
        guard !addresses.isEmpty else {
            return eventLoop.makeFailedFuture(SQLServerError.connectionClosed)
        }
        let race = Race(
            addresses: addresses, stagger: stagger, eventLoop: eventLoop, attempt: attempt,
            discard: discard, isUnreachable: isUnreachable, progress: progress
        )
        race.launchNext()
        return race.promise.futureResult
    }

    private final class Race<Connection: Sendable>: Sendable {
        let addresses: [SocketAddress]
        let stagger: TimeAmount
        let eventLoop: EventLoop
        let attempt: @Sendable (SocketAddress) -> EventLoopFuture<Connection>
        let discard: @Sendable (Connection) -> Void
        let isUnreachable: @Sendable (Error) -> Bool
        let progress: @Sendable (String) -> Void
        let promise: EventLoopPromise<Connection>
        let state = NIOLockedValueBox(State())

        init(
            addresses: [SocketAddress], stagger: TimeAmount, eventLoop: EventLoop,
            attempt: @escaping @Sendable (SocketAddress) -> EventLoopFuture<Connection>,
            discard: @escaping @Sendable (Connection) -> Void,
            isUnreachable: @escaping @Sendable (Error) -> Bool,
            progress: @escaping @Sendable (String) -> Void
        ) {
            self.addresses = addresses
            self.stagger = stagger
            self.eventLoop = eventLoop
            self.attempt = attempt
            self.discard = discard
            self.isUnreachable = isUnreachable
            self.progress = progress
            self.promise = eventLoop.makePromise(of: Connection.self)
        }

        private func report(_ s: State) {
            var parts: [String] = []
            if !s.pending.isEmpty { parts.append("no answer yet from \(s.pending.joined(separator: ", "))") }
            if !s.failed.isEmpty { parts.append("could not reach \(s.failed.joined(separator: ", "))") }
            progress("connecting: " + parts.joined(separator: "; "))
        }

        func launchNext() {
            let launched = state.withLockedValue { s -> SocketAddress? in
                guard !s.finished, s.launched < addresses.count else { return nil }
                let address = addresses[s.launched]
                s.launched += 1
                s.pending.append(SQLServerAddressRace.describe(address))
                if s.launched < addresses.count {
                    s.timers.append(eventLoop.scheduleTask(in: stagger) { self.launchNext() })
                }
                report(s)
                return address
            }
            guard let address = launched else { return }
            let name = SQLServerAddressRace.describe(address)
            attempt(address).whenComplete { result in
                switch result {
                case .success(let connection): self.succeeded(connection)
                case .failure(let error): self.failed(error, address: name)
                }
            }
        }

        private func succeeded(_ connection: Connection) {
            let won = state.withLockedValue { s -> Bool in
                guard !s.finished else { return false }
                s.finished = true
                s.timers.forEach { $0.cancel() }
                return true
            }
            if won { promise.succeed(connection) } else { discard(connection) }
        }

        private func failed(_ error: Error, address: String) {
            let next = state.withLockedValue { s -> Next in
                s.pending.removeAll { $0 == address }
                guard !s.finished else { return .ignore }
                if isUnreachable(error) {
                    s.failed.append(address)
                    report(s)
                    if s.failed.count < addresses.count { return .launch }
                }
                // Every address failed, or the server itself answered with a TLS or protocol failure.
                s.finished = true
                s.timers.forEach { $0.cancel() }
                return .fail
            }
            switch next {
            case .ignore: break
            case .fail: promise.fail(error)
            case .launch: launchNext()
            }
        }
    }
}
