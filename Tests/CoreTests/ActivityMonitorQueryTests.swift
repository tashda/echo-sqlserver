import XCTest
@testable import SQLServerKit

/// What the Activity Monitor asks the server for. The query plan of each of the twenty most expensive queries was
/// read on every refresh although nothing shows it: megabytes every five seconds, and seconds of server CPU.
final class ActivityMonitorQueryTests: XCTestCase {
    func testExpensiveQueriesAskForNoPlanUnlessAsked() {
        let plain = SQLServerActivityMonitor.expensiveQueriesSQL(options: .init())
        XCTAssertFalse(plain.contains("dm_exec_query_plan"))
        XCTAssertTrue(plain.contains("dm_exec_sql_text"))
        let withPlan = SQLServerActivityMonitor.expensiveQueriesSQL(options: .init(includeQueryPlan: true))
        XCTAssertTrue(withPlan.contains("dm_exec_query_plan"))
    }

    func testProcessesAskForNoPlanUnlessAsked() {
        XCTAssertFalse(SQLServerActivityMonitor.processesSQL(options: .init()).contains("dm_exec_query_plan"))
        XCTAssertTrue(SQLServerActivityMonitor.processesSQL(options: .init(includeQueryPlan: true)).contains("dm_exec_query_plan"))
    }

    func testTextCanBeLeftOutToo() {
        let noText = SQLServerActivityOptions(includeSqlText: false)
        XCTAssertFalse(SQLServerActivityMonitor.expensiveQueriesSQL(options: noText).contains("dm_exec_sql_text"))
        XCTAssertFalse(SQLServerActivityMonitor.processesSQL(options: noText).contains("dm_exec_sql_text"))
    }
}
