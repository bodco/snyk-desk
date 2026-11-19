import Foundation

/// The facts a report is written about.
public struct ReportContext: Sendable {
    public var repo: String
    public var project: String
    public var path: String
    public var scanDate: String
    public var filter: String
    public var generated: String

    public init(repo: String, project: String, path: String, scanDate: String, filter: String = "all findings",
                generated: String = ReportContext.now()) {
        self.repo = repo
        self.project = project
        self.path = path
        self.scanDate = scanDate
        self.filter = filter
        self.generated = generated
    }

    public static func now() -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH:mm"
        return formatter.string(from: Date())
    }
}

/// Builds the full vulnerability report in Markdown or HTML: grouped by severity,
/// every vulnerability with all the detail the scan has and links to deeper analysis.
public enum ReportBuilder {
    public static func links(for finding: Finding) -> [(title: String, url: String)] {
        var result: [(String, String)] = []
        if let url = finding.url {
            result.append((finding.kind == .dependency ? "Snyk vulnerability database" : "CWE description", url))
        }
        if finding.kind == .dependency {
            for cve in finding.cve ?? [] where cve.uppercased().hasPrefix("CVE-") {
                result.append((cve, "https://nvd.nist.gov/vuln/detail/\(cve)"))
            }
        }
        for cwe in finding.cwe ?? [] {
            if let number = Int(cwe.uppercased().replacingOccurrences(of: "CWE-", with: "")) {
                let url = "https://cwe.mitre.org/data/definitions/\(number).html"
                if !result.contains(where: { $0.1 == url }) { result.append((cwe, url)) }
            }
        }
        return result
    }

    static func grouped(_ findings: [Finding]) -> [(Severity, [Finding])] {
        Severity.allCases.compactMap { severity in
            let items = ResultParser.sorted(findings).filter { $0.severity == severity }
            return items.isEmpty ? nil : (severity, items)
        }
    }

    static func fields(_ f: Finding) -> [(String, String)] {
        var rows: [(String, String)] = [
            ("Type", f.kind == .dependency ? "Dependency" : "Code"),
            ("Identifier", f.issueId),
            ("Where", f.location),
        ]
        if f.kind == .dependency, !f.detail.isEmpty { rows.append(("Introduced through", f.detail)) }
        if f.kind == .code, !f.detail.isEmpty { rows.append(("What Snyk found", f.detail)) }
        if let score = f.score { rows.append(("CVSS score", String(format: "%.1f", score))) }
        if let cwe = f.cwe, !cwe.isEmpty { rows.append(("CWE", cwe.joined(separator: ", "))) }
        if let cve = f.cve, !cve.isEmpty { rows.append(("CVE", cve.joined(separator: ", "))) }
        if let fix = f.fix { rows.append(("Fix", fix)) }
        return rows
    }

    public static func summaryLine(_ counts: SeverityCounts) -> String {
        "Critical \(counts.critical), High \(counts.high), Medium \(counts.medium), Low \(counts.low)"
    }

    public static func markdown(findings: [Finding], run: ScanRun?, context: ReportContext) -> String {
        let counts = SeverityCounts.of(findings)
        var lines = [
            "# Snyk report: \(context.repo)",
            "",
            "- Project: \(context.project)",
            "- Repository: \(context.path)",
            "- Scan: \(context.scanDate)",
            "- Shown: \(context.filter)",
            "- Generated: \(context.generated)",
        ]
        if let run {
            lines.append("- Steps: dependencies \(run.dependencies.rawValue), code \(run.code.rawValue), monitor \(run.monitor.rawValue)")
        }
        lines += ["", "## Summary", "", "| Severity | Count |", "|---|---|",
                  "| Critical | \(counts.critical) |", "| High | \(counts.high) |",
                  "| Medium | \(counts.medium) |", "| Low | \(counts.low) |",
                  "| Total | \(findings.count) |"]
        if let run, !run.notes.isEmpty {
            lines += ["", "## Problems during the scan", ""] + run.notes.map { "- " + $0.replacingOccurrences(of: "\n", with: " ") }
        }
        if findings.isEmpty { lines += ["", "No vulnerabilities."] }
        var number = 0
        for (severity, items) in grouped(findings) {
            lines += ["", "## \(severity.label) (\(items.count))"]
            for finding in items {
                number += 1
                lines += ["", "### \(number). \(finding.title)", ""]
                for (name, value) in fields(finding) { lines.append("- **\(name):** \(value)") }
                if let advice = finding.advice {
                    lines += ["", "> " + advice.replacingOccurrences(of: "\n", with: "\n> ")]
                }
                let linkList = links(for: finding)
                if !linkList.isEmpty {
                    lines += ["", "Deeper analysis: " + linkList.map { "[\($0.title)](\($0.url))" }.joined(separator: " | ")]
                }
            }
        }
        return lines.joined(separator: "\n") + "\n"
    }

    static func escape(_ text: String) -> String {
        text.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
    }

    public static func html(findings: [Finding], run: ScanRun?, context: ReportContext) -> String {
        let counts = SeverityCounts.of(findings)
        let colors: [Severity: String] = [.critical: "#9e1420", .high: "#d9541a", .medium: "#b88a0d", .low: "#777777"]
        var out = """
        <html><head><meta charset="utf-8"><style>
        body { font-family: -apple-system, Helvetica, Arial, sans-serif; font-size: 10pt; color: #111; }
        h1 { font-size: 20pt; margin-bottom: 4pt; } h2 { font-size: 14pt; margin-top: 18pt; }
        h3 { font-size: 11pt; margin-bottom: 2pt; } td { padding: 1pt 8pt 1pt 0; vertical-align: top; }
        td.k { color: #555; white-space: nowrap; } .advice { color: #333; margin: 4pt 0; }
        .links { font-size: 9pt; } a { color: #1a4fa0; }
        </style></head><body>
        <h1>Snyk report: \(escape(context.repo))</h1>
        <p>Project: \(escape(context.project))<br>Repository: \(escape(context.path))<br>Scan: \(escape(context.scanDate))<br>Shown: \(escape(context.filter))<br>Generated: \(escape(context.generated))</p>
        <h2>Summary</h2>
        <table>
        """
        for (severity, count) in [(Severity.critical, counts.critical), (.high, counts.high), (.medium, counts.medium), (.low, counts.low)] {
            out += "<tr><td class=\"k\"><b style=\"color:\(colors[severity] ?? "#000")\">\(severity.label)</b></td><td>\(count)</td></tr>\n"
        }
        out += "<tr><td class=\"k\"><b>Total</b></td><td>\(findings.count)</td></tr></table>\n"
        if let run, !run.notes.isEmpty {
            out += "<h2>Problems during the scan</h2><ul>" + run.notes.map { "<li>\(escape($0))</li>" }.joined() + "</ul>\n"
        }
        if findings.isEmpty { out += "<p>No vulnerabilities.</p>\n" }
        var number = 0
        for (severity, items) in grouped(findings) {
            out += "<h2 style=\"color:\(colors[severity] ?? "#000")\">\(severity.label) (\(items.count))</h2>\n"
            for finding in items {
                number += 1
                out += "<h3>\(number). \(escape(finding.title))</h3><table>\n"
                for (name, value) in fields(finding) {
                    out += "<tr><td class=\"k\">\(escape(name))</td><td>\(escape(value))</td></tr>\n"
                }
                out += "</table>\n"
                if let advice = finding.advice { out += "<p class=\"advice\">\(escape(advice).replacingOccurrences(of: "\n", with: "<br>"))</p>\n" }
                let linkList = links(for: finding)
                if !linkList.isEmpty {
                    out += "<p class=\"links\">Deeper analysis: " + linkList.map { "<a href=\"\($0.url)\">\(escape($0.title))</a>" }.joined(separator: " | ") + "</p>\n"
                }
            }
        }
        return out + "</body></html>\n"
    }
}
