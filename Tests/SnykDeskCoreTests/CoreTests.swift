import XCTest
@testable import SnykDeskCore

final class ParserTests: XCTestCase {
    func testDependencyResultsArrayWithDuplicatesAndErrors() {
        let json = """
        [
          {"displayTargetFile": "package-lock.json", "vulnerabilities": [
            {"id": "SNYK-JS-A-1", "title": "Prototype Pollution", "severity": "high",
             "packageName": "lodash", "version": "4.17.20", "fixedIn": ["4.17.21"], "from": ["app@1.0.0", "lodash@4.17.20"]},
            {"id": "SNYK-JS-A-1", "title": "Prototype Pollution", "severity": "high",
             "packageName": "lodash", "version": "4.17.20", "fixedIn": ["4.17.21"]},
            {"id": "SNYK-JS-B-2", "title": "ReDoS", "severity": "critical", "packageName": "minimatch", "version": "3.0.4"}
          ]},
          {"ok": false, "error": "Could not resolve pom.xml", "vulnerabilities": []}
        ]
        """
        let result = ResultParser.parseDependencies(Data(json.utf8))
        XCTAssertEqual(result.projects, 2)
        XCTAssertEqual(result.findings.count, 2)
        XCTAssertEqual(result.findings.first?.severity, .critical)
        XCTAssertEqual(result.errors, ["Could not resolve pom.xml"])
        let lodash = result.findings.first { $0.issueId == "SNYK-JS-A-1" }
        XCTAssertEqual(lodash?.fix, "Upgrade lodash to 4.17.21")
        XCTAssertEqual(lodash?.location, "lodash@4.17.20 in package-lock.json")
        XCTAssertEqual(lodash?.detail, "app@1.0.0 > lodash@4.17.20")
    }

    func testDependencyResultsSingleObject() {
        let json = #"{"vulnerabilities": [{"id": "X", "severity": "low", "packageName": "p", "version": "1"}]}"#
        let result = ResultParser.parseDependencies(Data(json.utf8))
        XCTAssertEqual(result.projects, 1)
        XCTAssertEqual(result.findings.map(\.severity), [.low])
    }

    func testUnreadableResults() {
        let result = ResultParser.parseDependencies(Data("not json".utf8))
        XCTAssertTrue(result.findings.isEmpty)
        XCTAssertFalse(result.errors.isEmpty)
    }

    func testSarifCodeResults() {
        let json = """
        {"runs": [{
          "tool": {"driver": {"rules": [{"id": "javascript/XSS", "shortDescription": {"text": "Cross-site Scripting"}}]}},
          "results": [
            {"ruleId": "javascript/XSS", "level": "error", "message": {"text": "Unsanitized input flows into innerHTML"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/app.js"}, "region": {"startLine": 42}}}]},
            {"ruleId": "javascript/Other", "level": "note", "message": {"text": "Minor"}}
          ]
        }]}
        """
        let findings = ResultParser.parseCode(Data(json.utf8))
        XCTAssertEqual(findings.count, 2)
        XCTAssertEqual(findings[0].severity, .high)
        XCTAssertEqual(findings[0].title, "Cross-site Scripting")
        XCTAssertEqual(findings[0].location, "src/app.js:42")
        XCTAssertEqual(findings[1].severity, .low)
        XCTAssertEqual(findings[1].title, "javascript/Other")
    }

    func testExitCodes() {
        XCTAssertEqual(StepStatus.fromExit(0), .clean)
        XCTAssertEqual(StepStatus.fromExit(1), .issues)
        XCTAssertEqual(StepStatus.fromExit(2), .error)
        XCTAssertEqual(StepStatus.fromExit(3), .unsupported)
        XCTAssertEqual(StepStatus.fromExit(nil), .skipped)
    }

    func testLoadRunFromFolder() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let run = root.appendingPathComponent("2026-11-19T10-00-00")
        try FileManager.default.createDirectory(at: run, withIntermediateDirectories: true)
        try "1\n".write(to: run.appendingPathComponent("deps.exit"), atomically: true, encoding: .utf8)
        try "2\n".write(to: run.appendingPathComponent("code.exit"), atomically: true, encoding: .utf8)
        try "line one\nAuthentication failed\n".write(to: run.appendingPathComponent("code.log"), atomically: true, encoding: .utf8)
        try #"{"vulnerabilities": [{"id": "A", "severity": "medium", "packageName": "p", "version": "1"}]}"#
            .write(to: run.appendingPathComponent("deps.json"), atomically: true, encoding: .utf8)

        let loaded = ResultParser.loadRun(directory: run, repoId: UUID())
        XCTAssertEqual(loaded.dependencies, .issues)
        XCTAssertEqual(loaded.code, .error)
        XCTAssertEqual(loaded.monitor, .skipped)
        XCTAssertEqual(loaded.counts, SeverityCounts(medium: 1))
        XCTAssertTrue(loaded.notes.contains { $0.contains("Authentication failed") })
        let parts = Calendar.current.dateComponents([.year, .month, .day, .hour], from: loaded.date)
        XCTAssertEqual(parts.year, 2026)
        XCTAssertEqual(parts.hour, 10)
    }
}

final class UsageTests: XCTestCase {
    func testMonthlyUsageCountsOnlyThisMonth() {
        let now = Date()
        let lastYear = Calendar.current.date(byAdding: .year, value: -1, to: now)!
        func run(_ date: Date, deps: StepStatus, code: StepStatus, monitor: StepStatus, projects: Int) -> ScanRun {
            ScanRun(id: UUID().uuidString, repoId: UUID(), date: date, dependencies: deps, code: code,
                    monitor: monitor, dependencyProjects: projects, findings: [], notes: [])
        }
        let usage = UsageCalculator.thisMonth([
            run(now, deps: .issues, code: .clean, monitor: .clean, projects: 3),
            run(now, deps: .unsupported, code: .skipped, monitor: .skipped, projects: 0),
            run(lastYear, deps: .issues, code: .issues, monitor: .clean, projects: 5)
        ], now: now)
        XCTAssertEqual(usage, MonthlyUsage(openSource: 6, code: 1))
    }
}

final class LauncherTests: XCTestCase {
    func testShellQuote() {
        XCTAssertEqual(LauncherGenerator.shellQuote("a b"), "'a b'")
        XCTAssertEqual(LauncherGenerator.shellQuote("it's"), "'it'\\''s'")
    }

    func testScriptContainsReposAndIsValidBash() throws {
        var config = AppConfig()
        config.launcherFolder = "/tmp/launcher"
        let repo = RepoConfig(name: "Mike's app", path: "/tmp/mike app", project: "Acme", scanCode: false)
        let custom = RepoConfig(name: "Emily", path: "/tmp/emily", resultsFolder: "/tmp/scans/emily")
        config.repos = [repo, custom]
        let text = LauncherGenerator.script(config: config, snykPath: "/usr/local/bin/snyk", pathEnv: "/usr/bin:/bin")
        XCTAssertTrue(text.hasPrefix("#!/bin/bash\n"))
        XCTAssertTrue(text.contains(Paths.launcherMarker))
        XCTAssertTrue(text.contains("\(repo.id.uuidString)|Mike'\\''s app|/tmp/mike app|1|0|1|1|/tmp/launcher/Acme/mike app"))
        XCTAssertTrue(text.contains("\(custom.id.uuidString)|Emily|/tmp/emily|1|1|1|1|/tmp/scans/emily"))

        let file = FileManager.default.temporaryDirectory.appendingPathComponent("\(UUID().uuidString).sh")
        try text.write(to: file, atomically: true, encoding: .utf8)
        let check = Shell.run("/bin/bash", ["-n", file.path])
        XCTAssertEqual(check.status, 0, check.output)
    }

    func testStatusDetection() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        XCTAssertEqual(LauncherGenerator.status(in: folder.path), .missing)
        try "echo hi".write(to: LauncherGenerator.url(in: folder.path), atomically: true, encoding: .utf8)
        XCTAssertEqual(LauncherGenerator.status(in: folder.path), .foreign)
        Paths.rootOverride = folder.appendingPathComponent("support")
        defer { Paths.rootOverride = nil }
        try LauncherGenerator.install(config: AppConfig(), folder: folder.path, snykPath: "snyk", pathEnv: "/usr/bin")
        XCTAssertEqual(LauncherGenerator.status(in: folder.path), .installed)
    }
}

final class ResultsLocationTests: XCTestCase {
    func testDefaultIsNextToLauncherAndCustomWins() {
        var config = AppConfig()
        config.launcherFolder = "/Users/mike/work/Tools/security-scan"
        var repo = RepoConfig(name: "Renamed in app", path: "/Users/mike/work/acme/repos/backend")
        config.repos = [repo]
        XCTAssertEqual(repo.project, "acme")
        XCTAssertEqual(ResultsLocation.folder(for: repo, config: config), "/Users/mike/work/Tools/security-scan/acme/backend")
        repo.resultsFolder = "/Users/mike/work/Client/security-scan"
        XCTAssertEqual(ResultsLocation.folder(for: repo, config: config), "/Users/mike/work/Client/security-scan")
    }

    func testSameFolderNamesDoNotMix() {
        var config = AppConfig()
        config.launcherFolder = "/l"
        let first = RepoConfig(name: "a", path: "/one/api", project: "Acme")
        let second = RepoConfig(name: "b", path: "/two/api", project: "Acme")
        let other = RepoConfig(name: "c", path: "/three/api", project: "Globex")
        config.repos = [first, second, other]
        let a = ResultsLocation.folder(for: first, config: config)
        let b = ResultsLocation.folder(for: second, config: config)
        XCTAssertNotEqual(a, b)
        XCTAssertTrue(a.hasPrefix("/l/Acme/api-"))
        XCTAssertEqual(ResultsLocation.folder(for: other, config: config), "/l/Globex/api")
    }

    func testOldRepoConfigWithoutResultsFolderStillLoads() throws {
        let json = #"{"repos": [{"id": "6F9619FF-8B86-D011-B42D-00C04FC964FF", "name": "x", "path": "/x", "scanDependencies": true, "scanCode": false, "monitor": true, "scheduled": true}]}"#
        let config = try JSONDecoder().decode(AppConfig.self, from: Data(json.utf8))
        XCTAssertEqual(config.repos.count, 1)
        XCTAssertNil(config.repos[0].resultsFolder)
        XCTAssertEqual(config.repos[0].project, "Other")
        XCTAssertFalse(config.repos[0].scanCode)
    }

    func testLoadRunsIgnoresUnrelatedFolders() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: folder.appendingPathComponent("2026-11-01T09-00-00"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: folder.appendingPathComponent("2026-11-08T09-00-00"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: folder.appendingPathComponent("notes"), withIntermediateDirectories: true)
        var config = AppConfig()
        let repo = RepoConfig(name: "x", path: "/x", resultsFolder: folder.path)
        config.repos = [repo]
        let runs = ResultParser.loadRuns(repo: repo, config: config)
        XCTAssertEqual(runs.map(\.id), ["2026-11-08T09-00-00", "2026-11-01T09-00-00"])
    }
}

final class ProjectInferenceTests: XCTestCase {
    func testGuessesProjectFromPath() {
        XCTAssertEqual(ProjectInference.guess(path: "/Users/mike/work/Acme/repos/api-server"), "Acme")
        XCTAssertEqual(ProjectInference.guess(path: "/Users/mike/work/Acme/Repos/web"), "Acme")
        XCTAssertEqual(ProjectInference.guess(path: "/Users/mike/work/Globex/app"), "Globex")
        XCTAssertEqual(ProjectInference.guess(path: "/x"), "Other")
    }
}

final class ScheduleTests: XCTestCase {
    func testWeekdayMapping() {
        XCTAssertEqual(ScheduleWriter.launchdWeekday(1), 0) // Sunday
        XCTAssertEqual(ScheduleWriter.launchdWeekday(2), 1) // Monday
        XCTAssertEqual(ScheduleWriter.launchdWeekday(7), 6) // Saturday
    }

    func testPlistForWeeklyAndDaily() throws {
        var schedule = ScheduleConfig(enabled: true, frequency: .weekly, weekday: 2, hour: 9, minute: 30)
        var plist = ScheduleWriter.plist(launcher: "/x/snyk-desk-scan.sh", schedule: schedule, logDir: "/logs")
        XCTAssertEqual(plist["Label"] as? String, Paths.agentLabel)
        XCTAssertEqual(plist["ProgramArguments"] as? [String], ["/bin/bash", "/x/snyk-desk-scan.sh", "--scheduled"])
        XCTAssertEqual(plist["StartCalendarInterval"] as? [String: Int], ["Hour": 9, "Minute": 30, "Weekday": 1])

        schedule.frequency = .daily
        plist = ScheduleWriter.plist(launcher: "/x/snyk-desk-scan.sh", schedule: schedule, logDir: "/logs")
        XCTAssertEqual(plist["StartCalendarInterval"] as? [String: Int], ["Hour": 9, "Minute": 30])
        XCTAssertNoThrow(try ScheduleWriter.plistData(launcher: "/x", schedule: schedule, logDir: "/logs"))
    }

    func testNextRunIsOnTheRightWeekday() {
        let schedule = ScheduleConfig(enabled: true, frequency: .weekly, weekday: 4, hour: 8, minute: 15)
        let next = ScheduleWriter.nextRun(schedule)
        XCTAssertNotNil(next)
        let parts = Calendar.current.dateComponents([.weekday, .hour, .minute], from: next!)
        XCTAssertEqual(parts.weekday, 4)
        XCTAssertEqual(parts.hour, 8)
        XCTAssertEqual(parts.minute, 15)
    }

    func testConfigDecodesWithMissingKeys() throws {
        let config = try JSONDecoder().decode(AppConfig.self, from: Data(#"{"onboardingDone": true}"#.utf8))
        XCTAssertTrue(config.onboardingDone)
        XCTAssertTrue(config.repos.isEmpty)
        XCTAssertEqual(config.schedule, ScheduleConfig())
    }
}
