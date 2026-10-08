import Foundation
import NIOConcurrencyHelpers
import NIOCore
import NIOPosix
import Testing
@testable import SQLServerKit

/// A host with several addresses connects as fast as its reachable address,
/// as SSMS does. The attempts here are promises the test completes by hand.
struct AddressRaceTests {
    private struct Unreachable: Error {}
    private struct Refused: Error {}

    private func addresses() throws -> [SocketAddress] {
        [try SocketAddress(ipAddress: "192.168.1.5", port: 1433), try SocketAddress(ipAddress: "10.136.0.5", port: 1433)]
    }

    private func race(
        _ addresses: [SocketAddress],
        stagger: TimeAmount,
        on loop: EventLoop,
        attempts: [String: EventLoopPromise<String>],
        discarded: NIOLockedValueBox<[String]> = .init([]),
        started: NIOLockedValueBox<[String]> = .init([]),
        progress: NIOLockedValueBox<String> = .init("")
    ) -> EventLoopFuture<String> {
        SQLServerAddressRace.run(
            addresses: addresses,
            stagger: stagger,
            on: loop,
            attempt: { address in
                started.withLockedValue { $0.append(address.ipAddress ?? "") }
                return attempts[address.ipAddress ?? ""]!.futureResult
            },
            discard: { connection in discarded.withLockedValue { $0.append(connection) } },
            isUnreachable: { $0 is Unreachable },
            progress: { text in progress.withLockedValue { $0 = text } }
        )
    }

    @Test func describesAddressesAsPeopleWriteThem() throws {
        #expect(SQLServerAddressRace.describe(try SocketAddress(ipAddress: "10.0.0.5", port: 1433)) == "10.0.0.5:1433")
        #expect(SQLServerAddressRace.describe(try SocketAddress(ipAddress: "fe80::1", port: 1433)) == "[fe80::1]:1433")
    }

    @Test func secondAddressWinsWhileTheFirstNeverAnswers() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { group.shutdownGracefully { _ in } }
        let loop = group.next()
        let first = loop.makePromise(of: String.self)
        let second = loop.makePromise(of: String.self)
        let progress = NIOLockedValueBox("")
        let result = race(try addresses(), stagger: .milliseconds(20), on: loop,
                          attempts: ["192.168.1.5": first, "10.136.0.5": second], progress: progress)
        try await Task.sleep(for: .milliseconds(100))
        second.succeed("second")
        #expect(try await result.get() == "second")
        #expect(progress.withLockedValue { $0 }.contains("no answer yet from 192.168.1.5:1433"))
        first.fail(Unreachable())
    }

    @Test func aConnectionThatArrivesLateIsDiscarded() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { group.shutdownGracefully { _ in } }
        let loop = group.next()
        let first = loop.makePromise(of: String.self)
        let second = loop.makePromise(of: String.self)
        let discarded = NIOLockedValueBox<[String]>([])
        let result = race(try addresses(), stagger: .milliseconds(10), on: loop,
                          attempts: ["192.168.1.5": first, "10.136.0.5": second], discarded: discarded)
        try await Task.sleep(for: .milliseconds(50))
        second.succeed("second")
        #expect(try await result.get() == "second")
        first.succeed("first")
        try await Task.sleep(for: .milliseconds(50))
        #expect(discarded.withLockedValue { $0 } == ["first"])
    }

    @Test func unreachableAddressStartsTheNextAtOnce() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { group.shutdownGracefully { _ in } }
        let loop = group.next()
        let first = loop.makePromise(of: String.self)
        let second = loop.makePromise(of: String.self)
        let started = NIOLockedValueBox<[String]>([])
        // The head start is far longer than the test: only the failure can start the second address.
        let result = race(try addresses(), stagger: .seconds(60), on: loop,
                          attempts: ["192.168.1.5": first, "10.136.0.5": second], started: started)
        #expect(started.withLockedValue { $0 } == ["192.168.1.5"])
        first.fail(Unreachable())
        try await Task.sleep(for: .milliseconds(50))
        #expect(started.withLockedValue { $0 } == ["192.168.1.5", "10.136.0.5"])
        second.succeed("second")
        #expect(try await result.get() == "second")
    }

    @Test func anAnswerFromTheServerEndsTheRaceAtOnce() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { group.shutdownGracefully { _ in } }
        let loop = group.next()
        let first = loop.makePromise(of: String.self)
        let second = loop.makePromise(of: String.self)
        let started = NIOLockedValueBox<[String]>([])
        let result = race(try addresses(), stagger: .seconds(60), on: loop,
                          attempts: ["192.168.1.5": first, "10.136.0.5": second], started: started)
        first.fail(Refused())
        await #expect(throws: Refused.self) { try await result.get() }
        #expect(started.withLockedValue { $0 } == ["192.168.1.5"])
        second.fail(Unreachable())
    }

    @Test func failsWhenEveryAddressIsUnreachable() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { group.shutdownGracefully { _ in } }
        let loop = group.next()
        let first = loop.makePromise(of: String.self)
        let second = loop.makePromise(of: String.self)
        let progress = NIOLockedValueBox("")
        let result = race(try addresses(), stagger: .milliseconds(10), on: loop,
                          attempts: ["192.168.1.5": first, "10.136.0.5": second], progress: progress)
        try await Task.sleep(for: .milliseconds(50))
        first.fail(Unreachable())
        second.fail(Unreachable())
        await #expect(throws: Unreachable.self) { try await result.get() }
        #expect(progress.withLockedValue { $0 }.contains("could not reach 192.168.1.5:1433, 10.136.0.5:1433"))
    }
}
