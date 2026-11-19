import Foundation

/// Reads what the launcher wrote for one scan and turns it into findings.
public enum ResultParser {
    public static func sorted(_ findings: [Finding]) -> [Finding] {
        findings.sorted {
            if $0.severity != $1.severity { return $0.severity < $1.severity }
            return $0.title < $1.title
        }
    }

    /// Parses `snyk test --json-file-output` (one project object or an array of them).
    public static func parseDependencies(_ data: Data) -> (findings: [Finding], projects: Int, errors: [String]) {
        guard let object = try? JSONSerialization.jsonObject(with: data) else {
            return ([], 0, ["Dependency results could not be read."])
        }
        let projects: [[String: Any]]
        if let array = object as? [[String: Any]] {
            projects = array
        } else if let single = object as? [String: Any] {
            projects = [single]
        } else {
            return ([], 0, ["Unexpected dependency results format."])
        }

        var seen = Set<String>()
        var findings: [Finding] = []
        var errors: [String] = []
        for project in projects {
            if let error = project["error"] as? String { errors.append(error) }
            let target = (project["displayTargetFile"] as? String) ?? (project["targetFile"] as? String) ?? ""
            for vuln in (project["vulnerabilities"] as? [[String: Any]]) ?? [] {
                let vulnId = vuln["id"] as? String ?? "unknown"
                let package = (vuln["packageName"] as? String) ?? (vuln["moduleName"] as? String) ?? "?"
                let version = vuln["version"] as? String ?? "?"
                let key = "\(vulnId)|\(package)|\(version)"
                if seen.contains(key) { continue }
                seen.insert(key)
                let fixedIn = (vuln["fixedIn"] as? [String]) ?? []
                let fix = fixedIn.isEmpty ? nil : "Upgrade \(package) to \(fixedIn.joined(separator: ", "))"
                let cwes = ((vuln["identifiers"] as? [String: Any])?["CWE"] as? [String]) ?? []
                let cves = ((vuln["identifiers"] as? [String: Any])?["CVE"] as? [String]) ?? []
                let path = ((vuln["from"] as? [String]) ?? []).joined(separator: " > ")
                let location = target.isEmpty ? "\(package)@\(version)" : "\(package)@\(version) in \(target)"
                findings.append(Finding(
                    id: "dep|\(key)",
                    kind: .dependency,
                    severity: Severity(snyk: vuln["severity"] as? String ?? "low"),
                    title: vuln["title"] as? String ?? vulnId,
                    issueId: vulnId,
                    location: location,
                    detail: path,
                    fix: fix,
                    url: "https://security.snyk.io/vuln/\(vulnId)",
                    cwe: cwes.isEmpty ? nil : cwes,
                    advice: shorten(vuln["description"] as? String),
                    cve: cves.isEmpty ? nil : cves,
                    score: vuln["cvssScore"] as? Double))
            }
        }
        return (sorted(findings), projects.count, errors)
    }

    /// Link to the MITRE page of a CWE id like "CWE-79". Snyk Code results carry no link of their own.
    static func cweLink(_ cwe: String?) -> String? {
        guard let cwe, cwe.uppercased().hasPrefix("CWE-"), let number = Int(cwe.dropFirst(4)) else { return nil }
        return "https://cwe.mitre.org/data/definitions/\(number).html"
    }

    /// The "Details" part of a Snyk Code rule help text.
    static func detailsSection(_ markdown: String) -> String {
        guard let start = markdown.range(of: "## Details") else { return markdown }
        let rest = markdown[start.upperBound...]
        if let end = rest.range(of: "\n## ") { return String(rest[..<end.lowerBound]) }
        return String(rest)
    }

    static func shorten(_ text: String?, limit: Int = 900) -> String? {
        guard let text else { return nil }
        let cleaned = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleaned.isEmpty else { return nil }
        return cleaned.count > limit ? String(cleaned.prefix(limit)) + "..." : cleaned
    }

    /// Parses `snyk code test --sarif-file-output` (SARIF 2.1).
    public static func parseCode(_ data: Data) -> [Finding] {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [] }
        var findings: [Finding] = []
        for run in (object["runs"] as? [[String: Any]]) ?? [] {
            var rules: [String: String] = [:]
            var ruleCWE: [String: [String]] = [:]
            var ruleAdvice: [String: String] = [:]
            if let tool = run["tool"] as? [String: Any], let driver = tool["driver"] as? [String: Any] {
                for rule in (driver["rules"] as? [[String: Any]]) ?? [] {
                    guard let ruleId = rule["id"] as? String else { continue }
                    let short = (rule["shortDescription"] as? [String: Any])?["text"] as? String
                    rules[ruleId] = short ?? (rule["name"] as? String) ?? ruleId
                    ruleCWE[ruleId] = (rule["properties"] as? [String: Any])?["cwe"] as? [String] ?? []
                    if let markdown = (rule["help"] as? [String: Any])?["markdown"] as? String {
                        ruleAdvice[ruleId] = shorten(detailsSection(markdown))
                    }
                }
            }
            for result in (run["results"] as? [[String: Any]]) ?? [] {
                let ruleId = result["ruleId"] as? String ?? "unknown"
                let message = (result["message"] as? [String: Any])?["text"] as? String ?? ""
                var file = ""
                var line = 0
                if let locations = result["locations"] as? [[String: Any]],
                   let physical = locations.first?["physicalLocation"] as? [String: Any] {
                    file = (physical["artifactLocation"] as? [String: Any])?["uri"] as? String ?? ""
                    line = (physical["region"] as? [String: Any])?["startLine"] as? Int ?? 0
                }
                let severity: Severity
                switch result["level"] as? String ?? "note" {
                case "error": severity = .high
                case "warning": severity = .medium
                default: severity = .low
                }
                let location = line > 0 ? "\(file):\(line)" : file
                findings.append(Finding(
                    id: "code|\(ruleId)|\(location)|\(findings.count)",
                    kind: .code,
                    severity: severity,
                    title: rules[ruleId] ?? ruleId,
                    issueId: ruleId,
                    location: location,
                    detail: message,
                    url: cweLink(ruleCWE[ruleId]?.first),
                    cwe: (ruleCWE[ruleId]?.isEmpty ?? true) ? nil : ruleCWE[ruleId],
                    advice: ruleAdvice[ruleId]))
            }
        }
        return sorted(findings)
    }

    static let folderDate: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd'T'HH-mm-ss"
        return formatter
    }()

    static func exitCode(_ dir: URL, _ step: String) -> Int? {
        guard let text = try? String(contentsOf: dir.appendingPathComponent("\(step).exit"), encoding: .utf8) else { return nil }
        return Int(text.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    /// The lines of a Snyk log that say what went wrong. Boilerplate (Docs, Tip, ID, Status) is dropped.
    static func tail(_ url: URL, lines: Int = 3) -> String? {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return nil }
        let noise = ["Docs:", "Tip:", "ID:", "Status:", "Please see our documentation"]
        let rows = text.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { row in !row.isEmpty && !noise.contains { row.hasPrefix($0) } }
        guard !rows.isEmpty else { return nil }
        if let first = rows.firstIndex(where: { $0.hasPrefix("ERROR") || $0.hasPrefix("FATAL") }) {
            return rows[first...].prefix(lines).joined(separator: "\n")
        }
        return rows.suffix(lines).joined(separator: "\n")
    }

    /// Sub-projects Snyk could not read: a path line ending in ":" followed by "Something went wrong",
    /// or "Monitoring <path>..." followed by the same sentence.
    public static func failedSubProjects(log: String, base: String) -> [String] {
        let rows = log.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
        var failed: [String] = []
        for (index, row) in rows.enumerated() {
            var path: String?
            if row.hasPrefix("/"), row.hasSuffix(":") { path = String(row.dropLast()) }
            if row.hasPrefix("Monitoring "), row.hasSuffix("...") { path = String(row.dropFirst(11).dropLast(3)) }
            guard let found = path else { continue }
            let following = rows[(index + 1)...].prefix(3)
            if following.contains(where: { $0.hasPrefix("Something went wrong") }) {
                failed.append(found.hasPrefix(base) ? String(found.dropFirst(base.count)).trimmingCharacters(in: CharacterSet(charactersIn: "/")) : found)
            }
        }
        return failed
    }

    /// First Maven `[ERROR]` lines from the `mvn dependency:tree` run the launcher makes after a Snyk Maven failure.
    static func mavenReason(_ url: URL) -> String? {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return nil }
        let errors = text.split(separator: "\n").map(String.init).filter { $0.contains("[ERROR]") }
        guard !errors.isEmpty else { return nil }
        let first = errors.first { $0.contains("Failed to execute") || $0.contains("Could not") || $0.contains("Non-resolvable") } ?? errors[0]
        return String(first.prefix(400))
    }

    /// A plain next step for the Snyk errors that show up most.
    public static func hint(forLog text: String) -> String? {
        if text.contains("SNYK-OS-MAVEN-0018") {
            return "Hint: Maven could not resolve the dependencies. Usual causes: a private repository (check ~/.m2/settings.xml), a Java version the project does not build with, or a module that does not compile. maven.log in the scan folder has Maven's own error."
        }
        if text.contains("SNYK-CLI-0008") || text.contains("Could not detect supported target files") {
            return "Hint: Snyk found no supported manifest here. For Python it needs requirements.txt, Pipfile or poetry.lock (uv.lock needs a recent Snyk CLI). If this repository has nothing Snyk understands, turn off Dependencies and Monitor for it."
        }
        if text.contains("SNYK-CLI-0000") && text.contains("exit code: -2") {
            return "Hint: a tool Snyk needs is missing. Open Settings, Tools."
        }
        if text.contains("SNYK-0005") || text.contains("Authentication") {
            return "Hint: Snyk is not signed in. Open Settings and sign in again."
        }
        return nil
    }

    /// Loads one scan folder: `results/<repo-id>/<timestamp>/`.
    public static func loadRun(directory: URL, repoId: UUID, repoPath: String? = nil) -> ScanRun {
        let name = directory.lastPathComponent
        let date = folderDate.date(from: name)
            ?? ((try? FileManager.default.attributesOfItem(atPath: directory.path))?[.creationDate] as? Date)
            ?? Date.distantPast

        let deps = StepStatus.fromExit(exitCode(directory, "deps"))
        let code = StepStatus.fromExit(exitCode(directory, "code"))
        let monitor = StepStatus.fromExit(exitCode(directory, "monitor"))

        var findings: [Finding] = []
        var notes: [String] = []
        var projects = 0

        if let error = try? String(contentsOf: directory.appendingPathComponent("error.txt"), encoding: .utf8) {
            notes.append(error.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        if let data = try? Data(contentsOf: directory.appendingPathComponent("deps.json")) {
            let parsed = parseDependencies(data)
            findings += parsed.findings
            projects = parsed.projects
            notes += parsed.errors
        }
        if let data = try? Data(contentsOf: directory.appendingPathComponent("code.json")) {
            findings += parseCode(data)
        }
        for (step, status) in [("deps", deps), ("code", code), ("monitor", monitor)] where status == .error {
            if let lastLines = tail(directory.appendingPathComponent("\(step).log")) {
                notes.append("\(step): \(lastLines)")
            }
            if let text = try? String(contentsOf: directory.appendingPathComponent("\(step).log"), encoding: .utf8),
               let hint = hint(forLog: text) {
                notes.append(hint)
            }
        }
        if let maven = mavenReason(directory.appendingPathComponent("maven.log"))
            ?? mavenReason(directory.appendingPathComponent("deps.debug.log")) {
            notes.append("maven: \(maven)")
        }
        for step in ["deps", "monitor"] {
            guard let log = try? String(contentsOf: directory.appendingPathComponent("\(step).log"), encoding: .utf8) else { continue }
            let failed = failedSubProjects(log: log, base: repoPath ?? "")
            if !failed.isEmpty {
                let name = step == "deps" ? "dependencies" : "monitor"
                notes.append("\(name): Snyk could not read \(failed.joined(separator: ", ")). The rest of the repository was handled. See \(step).log.")
            }
        }
        return ScanRun(id: name, repoId: repoId, date: date, dependencies: deps, code: code, monitor: monitor,
                       dependencyProjects: projects, findings: sorted(findings), notes: notes, directory: directory)
    }

    /// All scans in one results folder: one subfolder per scan, named by its timestamp.
    public static func loadRuns(folder: URL, repoId: UUID, repoPath: String? = nil) -> [ScanRun] {
        guard let items = try? FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: nil) else {
            return []
        }
        return items
            .filter { (try? $0.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true }
            .filter { folderDate.date(from: $0.lastPathComponent) != nil }
            .map { loadRun(directory: $0, repoId: repoId, repoPath: repoPath) }
    }

    /// All scans of one repository, newest first. Also reads scans that 0.1.0 kept in Application Support.
    public static func loadRuns(repo: RepoConfig, config: AppConfig) -> [ScanRun] {
        let current = URL(fileURLWithPath: ResultsLocation.folder(for: repo, config: config), isDirectory: true)
        let legacy = Paths.results.appendingPathComponent(repo.id.uuidString, isDirectory: true)
        var runs = loadRuns(folder: current, repoId: repo.id, repoPath: repo.path)
        if legacy.standardizedFileURL != current.standardizedFileURL {
            let known = Set(runs.map(\.id))
            runs += loadRuns(folder: legacy, repoId: repo.id, repoPath: repo.path).filter { !known.contains($0.id) }
        }
        return runs.sorted { $0.date > $1.date }
    }
}

public struct MonthlyUsage: Equatable, Sendable {
    public static let openSourceLimit = 200
    public static let codeLimit = 100

    public var openSource: Int
    public var code: Int

    public init(openSource: Int = 0, code: Int = 0) {
        self.openSource = openSource
        self.code = code
    }
}

/// Local estimate of how many Free plan tests this month's scans used.
/// Snyk counts on its side; this only counts what this app ran.
public enum UsageCalculator {
    public static func thisMonth(_ runs: [ScanRun], now: Date = Date(), calendar: Calendar = .current) -> MonthlyUsage {
        var usage = MonthlyUsage()
        for run in runs where calendar.isDate(run.date, equalTo: now, toGranularity: .month) {
            let projects = max(run.dependencyProjects, 1)
            if run.dependencies.consumedTest { usage.openSource += projects }
            if run.monitor.consumedTest { usage.openSource += projects }
            if run.code.consumedTest { usage.code += 1 }
        }
        return usage
    }
}
