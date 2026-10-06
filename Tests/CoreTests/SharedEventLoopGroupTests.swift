import NIO
import XCTest
@testable import SQLServerKit

/// Clients made without a thread count share one set of event loops, so more connections do not mean more threads.
final class SharedEventLoopGroupTests: XCTestCase {
    func testTheDefaultGroupIsOneObjectForTheWholeProcess() {
        XCTAssertTrue(SQLServerClient.sharedEventLoopGroup === SQLServerClient.sharedEventLoopGroup)
    }

    func testTheSharedGroupHasAtMostFourLoops() {
        var loops = Set<Swift.ObjectIdentifier>()
        for _ in 0..<64 { loops.insert(Swift.ObjectIdentifier(SQLServerClient.sharedEventLoopGroup.next() as AnyObject)) }
        XCTAssertLessThanOrEqual(loops.count, 4)
        XCTAssertGreaterThanOrEqual(loops.count, 1)
    }
}
