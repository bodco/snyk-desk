import Foundation

/// Writes a readable copy of a scan next to the raw Snyk files, so the findings survive
/// even if the app, the Snyk account or the repository configuration changes.
/// `report.md` is for people (and for pasting into Claude), `summary.json` is for tools.
public enum ReportWriter {
    public static let reportName = "report.md"
    public static let summaryName = "summary.json"

    public static func markdown(run: ScanRun, repo: String, project: String, path: String) -> String {
        let counts = run.counts
        var lines = [
            "# \(repo) - Snyk scan \(run.id)",
            "",
            "- Project: \(project)",
            "- Path: \(path)",
            "- Dependencies: \(run.dependencies.rawValue), Code: \(run.code.rawValue), Monitor: \(run.monitor.rawValue)",
            "- Critical \(counts.critical), High \(counts.high), Medium \(counts.medium), Low \(counts.low)",
        ]
        if !run.notes.isEmpty {
            lines += ["", "## Notes", ""] + run.notes.map { "- " + $0.replacingOccurrences(of: "\n", with: " ") }
        }
        lines += ["", "## Findings", ""]
        if run.findings.isEmpty { lines.append("None.") }
        for (index, finding) in run.findings.enumerated() {
            lines.append("### \(index + 1). \(finding.title)")
            lines.append("")
            lines.append(PromptBuilder.findingText(finding).split(separator: "\n", omittingEmptySubsequences: false)
                .dropFirst().map { "- " + $0 }.joined(separator: "\n"))
            lines.append("")
        }
        return lines.joined(separator: "\n") + "\n"
    }

    public static func summaryJSON(run: ScanRun, repo: String, project: String, path: String) -> Data? {
        let counts = run.counts
        let object: [String: Any] = [
            "repo": repo, "project": project, "path": path, "scan": run.id,
            "dependencies": run.dependencies.rawValue, "code": run.code.rawValue, "monitor": run.monitor.rawValue,
            "counts": ["critical": counts.critical, "high": counts.high, "medium": counts.medium, "low": counts.low],
            "findings": run.findings.map { f -> [String: Any] in
                var item: [String: Any] = ["kind": f.kind.rawValue, "severity": f.severity.rawValue, "title": f.title,
                                           "id": f.issueId, "location": f.location]
                if let fix = f.fix { item["fix"] = fix }
                if let url = f.url { item["url"] = url }
                if let cwe = f.cwe { item["cwe"] = cwe }
                return item
            },
        ]
        return try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
    }

    /// Writes both files into the scan folder unless they are already there. Returns true when it wrote.
    @discardableResult
    public static func save(run: ScanRun, repo: String, project: String, path: String) -> Bool {
        guard let dir = run.directory else { return false }
        let report = dir.appendingPathComponent(reportName)
        guard !FileManager.default.fileExists(atPath: report.path) else { return false }
        // A scan that is still running has no "finished" marker yet; wait for it.
        guard FileManager.default.fileExists(atPath: dir.appendingPathComponent("finished").path) else { return false }
        try? markdown(run: run, repo: repo, project: project, path: path).write(to: report, atomically: true, encoding: .utf8)
        if let data = summaryJSON(run: run, repo: repo, project: project, path: path) {
            try? data.write(to: dir.appendingPathComponent(summaryName), options: .atomic)
        }
        return true
    }
}
