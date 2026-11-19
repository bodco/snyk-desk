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

final class ToolTests: XCTestCase {
    private func makeFolder(_ files: [String]) throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("tools-\(UUID().uuidString)")
        for file in files {
            let url = root.appendingPathComponent(file)
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try "x".write(to: url, atomically: true, encoding: .utf8)
        }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }

    func testCatalogIsConsistent() {
        let ids = ToolCatalog.all.map(\.id)
        XCTAssertEqual(Set(ids).count, ids.count)
        XCTAssertEqual(Set(ids), Set(ToolID.allCases))
        for spec in ToolCatalog.all {
            if case .download(_, let urls) = spec.install {
                XCTAssertFalse(urls.isEmpty, spec.title)
                XCTAssertTrue(urls.allSatisfy { $0.hasPrefix("https://") }, spec.title)
            }
        }
    }

    func testMavenProjectNeedsMavenAndJava() throws {
        let folder = try makeFolder(["pom.xml", "src/Main.java"])
        XCTAssertEqual(RepoRequirements.needs(path: folder.path), [.maven, .java])
    }

    func testGradleWrapperMeansNoGradleInstall() throws {
        let withWrapper = try makeFolder(["build.gradle", "gradlew"])
        XCTAssertEqual(RepoRequirements.needs(path: withWrapper.path), [.java])
        let without = try makeFolder(["build.gradle.kts"])
        XCTAssertEqual(RepoRequirements.needs(path: without.path), [.java, .gradle])
    }

    func testNodeNeededOnlyWithoutLockFile() throws {
        let locked = try makeFolder(["package.json", "package-lock.json"])
        XCTAssertEqual(RepoRequirements.needs(path: locked.path), [])
        let loose = try makeFolder(["web/package.json"])
        XCTAssertEqual(RepoRequirements.needs(path: loose.path), [.node])
    }

    func testGoPythonAndSwift() throws {
        XCTAssertEqual(RepoRequirements.needs(path: try makeFolder(["go.mod"]).path), [.go])
        XCTAssertEqual(RepoRequirements.needs(path: try makeFolder(["requirements.txt"]).path), [.commandLineTools])
        XCTAssertEqual(RepoRequirements.needs(path: try makeFolder(["Package.swift"]).path), [.commandLineTools])
    }

    func testBuildOutputAndHiddenFoldersAreIgnored() throws {
        let folder = try makeFolder(["node_modules/dep/pom.xml", "target/pom.xml", ".git/pom.xml", "README.md"])
        XCTAssertEqual(RepoRequirements.needs(path: folder.path), [])
    }

    func testOnlyDependencyScansNeedTools() throws {
        let folder = try makeFolder(["pom.xml"])
        var repo = RepoConfig(name: "api", path: folder.path)
        XCTAssertEqual(RepoRequirements.needs(for: [repo])[.maven], ["api"])
        repo.scanDependencies = false
        repo.monitor = false
        XCTAssertTrue(RepoRequirements.needs(for: [repo]).isEmpty)
    }

    func testManagedToolsAreFoundAndAddedToPath() throws {
        let support = FileManager.default.temporaryDirectory.appendingPathComponent("support-\(UUID().uuidString)")
        Paths.rootOverride = support
        defer { Paths.rootOverride = nil }

        func install(_ relative: String, script: String) throws {
            let file = support.appendingPathComponent("tools").appendingPathComponent(relative)
            try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
            try script.write(to: file, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: file.path)
        }
        XCTAssertFalse(ToolCatalog.isManagedInstalled(.maven))
        XCTAssertNil(ToolCatalog.managedJavaHome())

        try install("maven/bin/mvn", script: "#!/bin/sh\necho mvn\n")
        try install("java/Contents/Home/bin/java", script: "#!/bin/sh\necho 'openjdk version \"21.0.1\"' >&2\n")

        XCTAssertTrue(ToolCatalog.isManagedInstalled(.maven))
        XCTAssertTrue(ToolCatalog.managedBinDirs().contains(ToolCatalog.managedBin(.maven).path))
        XCTAssertTrue(Shell.commonDirs.contains(ToolCatalog.managedBin(.maven).path))
        XCTAssertEqual(ToolCatalog.managedJavaHome(), support.appendingPathComponent("tools/java/Contents/Home").path)
        XCTAssertEqual(Shell.environment(path: "/usr/bin")["JAVA_HOME"], ToolCatalog.managedJavaHome())

        let maven = ToolDetector.detect(ToolCatalog.spec(.maven), path: "/nonexistent")
        guard case .found(_, _, let managed) = maven else { return XCTFail("maven not found") }
        XCTAssertTrue(managed)

        let java = ToolDetector.detect(ToolCatalog.spec(.java), path: "/nonexistent")
        guard case .found(_, let version, let javaManaged) = java else { return XCTFail("java not found") }
        XCTAssertTrue(javaManaged)
        XCTAssertTrue(version.contains("21.0.1"), version)

        XCTAssertEqual(ToolDetector.detect(ToolCatalog.spec(.gradle), path: "/nonexistent"), .missing)
    }

    func testUnpackMovesSingleTopLevelFolder() throws {
        let work = FileManager.default.temporaryDirectory.appendingPathComponent("unpack-\(UUID().uuidString)")
        let source = work.appendingPathComponent("src/tool-1.0/bin")
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
        try "hi".write(to: source.appendingPathComponent("tool"), atomically: true, encoding: .utf8)
        let archive = work.appendingPathComponent("tool.tar.gz")
        let made = Shell.run("/usr/bin/tar", ["-czf", archive.path, "-C", work.appendingPathComponent("src").path, "tool-1.0"])
        XCTAssertEqual(made.status, 0, made.output)

        let destination = work.appendingPathComponent("tools/tool")
        try ToolUnpacker.unpack(archive: archive, kind: .tarGz, into: destination)
        XCTAssertTrue(FileManager.default.fileExists(atPath: destination.appendingPathComponent("bin/tool").path))
        // Installing again replaces the old copy.
        try ToolUnpacker.unpack(archive: archive, kind: .tarGz, into: destination)
        XCTAssertTrue(FileManager.default.fileExists(atPath: destination.appendingPathComponent("bin/tool").path))
    }

    func testUnpackRejectsOddLayout() throws {
        let work = FileManager.default.temporaryDirectory.appendingPathComponent("odd-\(UUID().uuidString)")
        let source = work.appendingPathComponent("src")
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
        try "a".write(to: source.appendingPathComponent("a"), atomically: true, encoding: .utf8)
        try "b".write(to: source.appendingPathComponent("b"), atomically: true, encoding: .utf8)
        let archive = work.appendingPathComponent("odd.tar.gz")
        _ = Shell.run("/usr/bin/tar", ["-czf", archive.path, "-C", source.path, "a", "b"])
        XCTAssertThrowsError(try ToolUnpacker.unpack(archive: archive, kind: .tarGz,
                                                     into: work.appendingPathComponent("tools/odd")))
    }

    func testLauncherCarriesJavaHomeAndPreflight() throws {
        var config = AppConfig()
        config.repos = [RepoConfig(name: "api", path: "/tmp/api")]
        let text = LauncherGenerator.script(config: config, snykPath: "/usr/local/bin/snyk",
                                            pathEnv: "/usr/bin:/bin", javaHome: "/Apps/jdk home")
        XCTAssertTrue(text.contains("export JAVA_HOME='/Apps/jdk home'"))
        XCTAssertTrue(text.contains("Open Snyk Desk, Settings, Tools"))
        XCTAssertTrue(text.contains("skip_step"))
        let plain = LauncherGenerator.script(config: config, snykPath: "snyk", pathEnv: "/usr/bin")
        XCTAssertFalse(plain.contains("export JAVA_HOME"))

        let file = FileManager.default.temporaryDirectory.appendingPathComponent("\(UUID().uuidString).sh")
        try text.write(to: file, atomically: true, encoding: .utf8)
        XCTAssertEqual(Shell.run("/bin/bash", ["-n", file.path]).status, 0)
    }

    func testHintsForCommonSnykErrors() {
        XCTAssertTrue(ResultParser.hint(forLog: "ERROR Cannot build Maven dependency tree (SNYK-OS-MAVEN-0018)")?.contains("maven.log") == true)
        XCTAssertTrue(ResultParser.hint(forLog: "FATAL No supported files found (SNYK-CLI-0008)")?.contains("manifest") == true)
        XCTAssertTrue(ResultParser.hint(forLog: "SNYK-CLI-0000 Child process failed with exit code: -2")?.contains("Tools") == true)
        XCTAssertNil(ResultParser.hint(forLog: "all good"))
    }

    func testRunFolderShowsMavenReasonAndPartialMonitorNote() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try "SNYK-OS-MAVEN-0018".write(to: dir.appendingPathComponent("deps.log"), atomically: true, encoding: .utf8)
        try "2".write(to: dir.appendingPathComponent("deps.exit"), atomically: true, encoding: .utf8)
        try "[INFO] x\n[ERROR] Could not transfer artifact foo from private-repo\n".write(
            to: dir.appendingPathComponent("maven.log"), atomically: true, encoding: .utf8)
        try "Some sub-projects could not be monitored.".write(
            to: dir.appendingPathComponent("monitor.note"), atomically: true, encoding: .utf8)
        let run = ResultParser.loadRun(directory: dir, repoId: UUID())
        XCTAssertEqual(run.directory, dir)
        XCTAssertTrue(run.notes.contains { $0.hasPrefix("maven: [ERROR] Could not transfer") })
        XCTAssertTrue(run.notes.contains { $0.hasPrefix("Hint: Maven") })
        XCTAssertTrue(run.notes.contains { $0.hasPrefix("monitor: Some sub-projects") })
    }

    func testLauncherWritesScanLogAndTreatsPartialMonitorAsDone() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let repo = root.appendingPathComponent("repo")
        try FileManager.default.createDirectory(at: repo, withIntermediateDirectories: true)
        let fake = root.appendingPathComponent("snyk")
        try """
        #!/bin/bash
        if [ "$1" = "--version" ]; then echo 9.9.9; exit 0; fi
        if [ "$1" = "monitor" ]; then echo "Explore this snapshot at x"; echo "Something went wrong"; exit 2; fi
        exit 0
        """.write(to: fake, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: fake.path)
        var config = AppConfig()
        config.launcherFolder = root.path
        let item = RepoConfig(name: "demo", path: repo.path, scanCode: false)
        config.repos = [item]
        let launcher = try LauncherGenerator.install(config: config, folder: root.path, snykPath: fake.path,
                                                     pathEnv: "/usr/bin:/bin")
        let result = Shell.run("/bin/bash", [launcher.path, item.id.uuidString])
        XCTAssertEqual(result.status, 0, result.output)
        let results = URL(fileURLWithPath: ResultsLocation.folder(for: item, config: config))
        let scanDir = try XCTUnwrap(FileManager.default.contentsOfDirectory(at: results, includingPropertiesForKeys: nil).first)
        let log = try String(contentsOf: scanDir.appendingPathComponent("scan.log"), encoding: .utf8)
        XCTAssertTrue(log.contains("snyk: 9.9.9"))
        XCTAssertTrue(log.contains("monitor: partial success"))
        XCTAssertEqual(ResultParser.exitCode(scanDir, "monitor"), 0)
        XCTAssertTrue(FileManager.default.fileExists(atPath: scanDir.appendingPathComponent("monitor.note").path))
    }

    func testAppLogWritesAndRotates() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        Paths.rootOverride = root
        defer { Paths.rootOverride = nil }
        AppLog.write("hello")
        XCTAssertTrue(try String(contentsOf: AppLog.file, encoding: .utf8).contains("hello"))
        try String(repeating: "x", count: AppLog.maxBytes + 10).write(to: AppLog.file, atomically: true, encoding: .utf8)
        AppLog.write("after")
        XCTAssertTrue(FileManager.default.fileExists(atPath: Paths.logs.appendingPathComponent("snyk-desk.old.log").path))
        XCTAssertTrue(try String(contentsOf: AppLog.file, encoding: .utf8).contains("after"))
    }

    func testCodeFindingsGetCweLinkAndAdvice() throws {
        let sarif = """
        {"runs":[{"tool":{"driver":{"rules":[{"id":"python/XSS","shortDescription":{"text":"Cross-site Scripting (XSS)"},
        "help":{"markdown":"\\n## Details\\n\\nUnsanitized input is rendered.\\n\\n## Best practices\\n* x"},
        "properties":{"cwe":["CWE-79"]}}]}},
        "results":[{"ruleId":"python/XSS","level":"error","message":{"text":"Unsanitized input"},
        "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},"region":{"startLine":3}}}]}]}]}
        """
        let found = ResultParser.parseCode(Data(sarif.utf8))
        XCTAssertEqual(found.count, 1)
        XCTAssertEqual(found[0].url, "https://cwe.mitre.org/data/definitions/79.html")
        XCTAssertEqual(found[0].cwe, ["CWE-79"])
        XCTAssertEqual(found[0].advice, "Unsanitized input is rendered.")
    }

    func testPromptsCarryRepoFilterAndFindings() {
        let a = Finding(id: "1", kind: .code, severity: .high, title: "XSS", issueId: "python/XSS",
                        location: "a.py:3", detail: "bad", url: "https://x")
        let b = Finding(id: "2", kind: .dependency, severity: .critical, title: "RCE", issueId: "SNYK-1",
                        location: "lib@1", detail: "app > lib", fix: "Upgrade lib to 2")
        let text = PromptBuilder.repoPrompt(findings: [a, b], repo: "server", project: "Acme", path: "/code/server",
                                            filter: "High і вище", scanDate: "today")
        XCTAssertTrue(text.contains("/code/server"))
        XCTAssertTrue(text.contains("High і вище"))
        XCTAssertTrue(text.contains("Critical 1, High 1"))
        XCTAssertTrue(text.range(of: "RCE")!.lowerBound < text.range(of: "XSS")!.lowerBound)
        let single = PromptBuilder.singlePrompt(a, repo: "server", project: "Acme", path: "/code/server")
        XCTAssertTrue(single.contains("a.py:3"))
        XCTAssertTrue(single.contains("Link: https://x"))
    }

    func testLongPromptListsTheRestByTitle() {
        let many = (0..<(PromptBuilder.fullLimit + 5)).map {
            Finding(id: "\($0)", kind: .code, severity: .low, title: "T\($0)", issueId: "r", location: "f:\($0)", detail: "")
        }
        let text = PromptBuilder.repoPrompt(findings: many, repo: "r", project: "p", path: "/p", filter: "f", scanDate: "d")
        XCTAssertTrue(text.contains("Ще 5 без деталей"))
    }

    func testVersionComparison() {
        XCTAssertTrue(Updater.isNewer("v0.2.10", than: "0.2.9"))
        XCTAssertTrue(Updater.isNewer("0.3.0", than: "0.2.9"))
        XCTAssertFalse(Updater.isNewer("0.2.2", than: "0.2.2"))
        XCTAssertFalse(Updater.isNewer("0.2.1", than: "0.2.2"))
        XCTAssertFalse(Updater.isNewer("0.2.2", than: "0.2.2-dev"))
        XCTAssertTrue(Updater.isNewer("0.2.3", than: "0.0.0-dev"))
    }

    func testParsesLatestRelease() {
        let json = """
        {"tag_name":"v0.2.3","body":"notes","assets":[{"name":"x.txt","browser_download_url":"https://a/x.txt"},
        {"name":"SnykDesk-0.2.3.zip","browser_download_url":"https://github.com/bodco/snyk-desk/releases/download/v0.2.3/SnykDesk-0.2.3.zip"}]}
        """
        let info = Updater.parse(Data(json.utf8), current: "0.2.2")
        XCTAssertEqual(info?.version, "0.2.3")
        XCTAssertTrue(info?.assetURL.hasSuffix("SnykDesk-0.2.3.zip") == true)
        XCTAssertNil(Updater.parse(Data(json.utf8), current: "0.2.3"))
        XCTAssertNil(Updater.parse(Data("{\"tag_name\":\"v9.0.0\",\"assets\":[]}".utf8), current: "0.2.2"))
        XCTAssertNil(Updater.parse(Data("nonsense".utf8), current: "0.2.2"))
    }

    func testSwapScriptIsValidBashAndQuotesPaths() throws {
        let text = Updater.swapScript(pid: 123, newApp: "/tmp/it's/Snyk Desk.app", destination: "/Applications/Snyk Desk.app")
        XCTAssertTrue(text.contains("kill -0 123"))
        XCTAssertTrue(text.contains("'/tmp/it'\\''s/Snyk Desk.app'"))
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("\(UUID().uuidString).sh")
        try text.write(to: file, atomically: true, encoding: .utf8)
        XCTAssertEqual(Shell.run("/bin/bash", ["-n", file.path]).status, 0)
    }

    func testLogoutClearsBothTokens() {
        let flat = SnykAuth.logoutCommands.map { $0.joined(separator: " ") }
        XCTAssertTrue(flat.contains("config unset api"))
        XCTAssertTrue(flat.contains("config unset INTERNAL_OAUTH_TOKEN_STORAGE"))
    }
}
