import XCTest
@testable import SRPTests

XCTMain([
     testCase(SRPTests.allTests),
     testCase(PySrptoolsTests.allTests),
     testCase(ReadmeTests.allTests)
])
