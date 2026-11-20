import AppKit
import SwiftUI
import SnykDeskCore

struct ProjectsView: View {
    @EnvironmentObject private var model: AppModel
    @Binding var selected: UUID?

    var body: some View {
        if model.config.repos.isEmpty {
            ContentUnavailableView {
                Label("No repositories yet", systemImage: "folder.badge.plus")
            } description: {
                Text("Add repository folders to scan them one by one.")
            } actions: {
                Button("Add repositories…") { model.addRepos() }
            }
        } else {
            HSplitView {
                List(selection: $selected) {
                    ForEach(model.projects, id: \.self) { project in
                        Section {
                            ForEach(model.repos(in: project)) { repo in
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(repo.name).font(.headline)
                                    if let run = model.latestRun(repo.id) {
                                        CountsRow(counts: run.counts).scaleEffect(0.85, anchor: .leading)
                                    } else {
                                        Text("Not scanned").font(.caption).foregroundStyle(.secondary)
                                    }
                                }
                                .padding(.vertical, 2)
                                .tag(repo.id)
                            }
                        } header: {
                            HStack {
                                Text(project)
                                Spacer()
                                Button {
                                    model.scanProject(project)
                                } label: {
                                    Image(systemName: "play.fill")
                                }
                                .buttonStyle(.borderless)
                                .help("Scan all repositories of \(project)")
                                .disabled(model.activeScan != nil)
                            }
                        }
                    }
                }
                .frame(minWidth: 230, idealWidth: 260, maxWidth: 320)

                detail
                    .frame(minWidth: 520, maxWidth: .infinity, maxHeight: .infinity)
            }
        }
    }

    @ViewBuilder
    private var detail: some View {
        let id = selected ?? model.config.repos.first?.id
        if let id, let index = model.config.repos.firstIndex(where: { $0.id == id }) {
            ProjectDetail(repo: $model.config.repos[index])
                .id(id)
        } else {
            Text("Select a repository").foregroundStyle(.secondary)
        }
    }
}

struct ProjectDetail: View {
    enum KindFilter: String, CaseIterable, Identifiable {
        case all = "All"
        case dependencies = "Dependencies"
        case code = "Code"
        var id: String { rawValue }
    }

    @EnvironmentObject private var model: AppModel
    @Binding var repo: RepoConfig
    @State private var runId: String?
    @State private var filter: KindFilter = .all
    @State private var minimum: Severity = .low
    @State private var showIgnored = false
    @State private var ignoring: Finding?

    private var runs: [ScanRun] { model.runs[repo.id] ?? [] }
    private var run: ScanRun? { runs.first { $0.id == runId } ?? runs.first }
    private var split: (open: [Finding], ignored: [(finding: Finding, rule: IgnoreRule)]) {
        run?.splitIgnored(model.config.ignores) ?? ([], [])
    }
    private var shownRun: ScanRun? { run?.withoutIgnored(model.config.ignores) }

    private var findings: [Finding] {
        guard run != nil else { return [] }
        let pool = showIgnored ? split.ignored.map(\.finding) : split.open
        return pool.filter { finding in
            let kindOK: Bool
            switch filter {
            case .all: kindOK = true
            case .dependencies: kindOK = finding.kind == .dependency
            case .code: kindOK = finding.kind == .code
            }
            return kindOK && finding.severity <= minimum
        }
    }

    private var filterDescription: String {
        let severity: String
        switch minimum {
        case .low: severity = "усі рівні"
        case .medium: severity = "Medium і вище"
        case .high: severity = "High і вище"
        case .critical: severity = "тільки Critical"
        }
        let kind: String
        switch filter {
        case .all: kind = "залежності і код"
        case .dependencies: kind = "тільки залежності"
        case .code: kind = "тільки код"
        }
        return "\(severity), \(kind)"
    }

    private func scanDate(_ run: ScanRun) -> String { run.date.formatted(date: .abbreviated, time: .shortened) }

    private func repoPrompt(_ items: [Finding], filter: String, sameIssue: String?, run: ScanRun) -> String {
        PromptBuilder.repoPrompt(findings: items, repo: repo.name, project: repo.project, path: repo.path,
                                 filter: filter, scanDate: scanDate(run), sameIssue: sameIssue)
    }

    private func saveReport(_ format: ReportFormat, run: ScanRun) {
        let context = ReportContext(repo: repo.name, project: repo.project, path: repo.path,
                                    scanDate: scanDate(run), filter: filterDescription)
        if let error = ReportExport.save(format: format, findings: findings, run: run, context: context) {
            model.lastError = error
        }
    }

    private func singlePrompt(_ finding: Finding) -> String {
        PromptBuilder.singlePrompt(finding, repo: repo.name, project: repo.project, path: repo.path)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(repo.name).font(.title2.bold())
                    Text("Project: \(repo.project)").font(.callout).foregroundStyle(.secondary)
                    Text(repo.path).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                }
                Spacer()
                if let run, !split.open.isEmpty {
                    Menu {
                        ForEach(ReportFormat.allCases, id: \.self) { format in
                            Button("Save as \(format.rawValue)…") { saveReport(format, run: run) }
                        }
                    } label: {
                        Label("Report", systemImage: "doc.text")
                    }
                    .fixedSize()
                    .help("A full report of the vulnerabilities shown now (the filters apply), grouped by severity with every detail and links for deeper analysis")
                }
                Button {
                    model.scan([repo.id])
                } label: {
                    Label("Scan now", systemImage: "play.fill")
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.activeScan != nil)
            }

            HStack(spacing: 18) {
                Toggle("Dependencies", isOn: $repo.scanDependencies)
                Toggle("Code", isOn: $repo.scanCode)
                Toggle("Snapshot to Snyk (monitor)", isOn: $repo.monitor)
            }
            .toggleStyle(.checkbox)

            ResultsFolderRow(repo: repo)

            MissingToolsBanner(repo: repo)

            if let scan = model.activeScan, scan.repoIds.contains(repo.id) {
                ScanProgressView(scan: scan)
            }

            if runs.isEmpty {
                ContentUnavailableView("Not scanned yet", systemImage: "shield",
                                       description: Text("Press Scan now to see this repository's vulnerabilities."))
            } else if let run {
                HStack(spacing: 12) {
                    Picker("Scan", selection: Binding(get: { run.id }, set: { runId = $0 })) {
                        ForEach(runs) { item in
                            Text(item.date.formatted(date: .abbreviated, time: .shortened)).tag(item.id)
                        }
                    }
                    .frame(maxWidth: 260)
                    Picker("Show", selection: $showIgnored) {
                        Text("Open (\(split.open.count))").tag(false)
                        Text("Ignored (\(split.ignored.count))").tag(true)
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .frame(maxWidth: 220)
                    Spacer()
                    Picker("Severity", selection: $minimum) {
                        Text("All").tag(Severity.low)
                        Text("Medium and up").tag(Severity.medium)
                        Text("High and up").tag(Severity.high)
                        Text("Critical").tag(Severity.critical)
                    }
                    .frame(maxWidth: 200)
                    Picker("Type", selection: $filter) {
                        ForEach(KindFilter.allCases) { Text($0.rawValue).tag($0) }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .frame(maxWidth: 280)
                    Button {
                        Clipboard.copy(repoPrompt(findings, filter: filterDescription, sameIssue: nil, run: run))
                    } label: {
                        Label("Copy to Claude", systemImage: "doc.on.doc")
                    }
                    .disabled(findings.isEmpty)
                    .help("Copies a prompt with the vulnerabilities shown now (the severity and type filters apply). Paste it into a Claude project that has the code.")
                }

                RunSummary(run: shownRun ?? run) { filter = $0; minimum = .low; showIgnored = false }

                if findings.isEmpty {
                    ContentUnavailableView(showIgnored ? "Nothing ignored" : "No vulnerabilities", systemImage: "checkmark.shield",
                                           description: Text(showIgnored ? "No ignored vulnerabilities match the filters." : "Nothing matches the filters in this scan."))
                } else {
                    let rules = Dictionary(split.ignored.map { ($0.finding.id, $0.rule) }, uniquingKeysWith: { first, _ in first })
                    List(findings) { finding in
                        FindingRow(finding: finding,
                                   ignoredRule: rules[finding.id],
                                   ignore: { ignoring = finding },
                                   unignore: { if let rule = rules[finding.id] { model.unignore(rule) } },
                                   copyDetails: { Clipboard.copy(PromptBuilder.findingText(finding)) },
                                   copyPrompt: { Clipboard.copy(singlePrompt(finding)) },
                                   copySameType: {
                                       let same = run.findings.filter { $0.issueId == finding.issueId && $0.kind == finding.kind }
                                       Clipboard.copy(repoPrompt(same, filter: "тип \(finding.title)", sameIssue: finding.title, run: run))
                                   },
                                   sameTypeCount: run.findings.filter { $0.issueId == finding.issueId && $0.kind == finding.kind }.count)
                    }
                    .listStyle(.inset)
                }
            }
        }
        .padding(20)
        .sheet(item: $ignoring) { finding in
            IgnoreSheet(finding: finding) { reason, comment, days in
                model.ignore(finding, repoId: repo.id, reason: reason, comment: comment, days: days)
            }
        }
    }
}

struct IgnoreSheet: View {
    let finding: Finding
    let onIgnore: (IgnoreReason, String, Int?) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var reason: IgnoreReason = .temporary
    @State private var days = 30
    @State private var comment = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Ignore this vulnerability").font(.title3.bold())
            VStack(alignment: .leading, spacing: 2) {
                Text(finding.title).font(.body.bold())
                Text(finding.location).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
            }
            Picker("Reason", selection: $reason) {
                ForEach(IgnoreReason.allCases, id: \.self) { Text($0.label).tag($0) }
            }
            Picker("Ignore for", selection: $days) {
                Text("30 days").tag(30)
                Text("60 days").tag(60)
                Text("90 days").tag(90)
                Text("Never expires").tag(0)
            }
            VStack(alignment: .leading, spacing: 4) {
                Text("Comment").font(.caption).foregroundStyle(.secondary)
                TextEditor(text: $comment)
                    .font(.body)
                    .frame(height: 70)
                    .overlay(RoundedRectangle(cornerRadius: 4).stroke(Color.secondary.opacity(0.3)))
            }
            Text("Kept in this app only. It hides the vulnerability from the lists, counts and reports and nothing is written into the repository. It comes back after the date, or when you press Unignore.")
                .font(.caption).foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Ignore") {
                    onIgnore(reason, comment.trimmingCharacters(in: .whitespacesAndNewlines), days == 0 ? nil : days)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(20)
        .frame(width: 460)
    }
}

struct RunSummary: View {
    let run: ScanRun
    var onPick: (ProjectDetail.KindFilter) -> Void = { _ in }
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 16) {
                CountsRow(counts: run.counts)
                Spacer()
                StepStatusLabel(title: "Dependencies", status: run.dependencies,
                                count: run.findings.filter { $0.kind == .dependency }.count) { onPick(.dependencies) }
                StepStatusLabel(title: "Code", status: run.code,
                                count: run.findings.filter { $0.kind == .code }.count) { onPick(.code) }
                StepStatusLabel(title: "Monitor", status: run.monitor)
            }
            ForEach(run.notes, id: \.self) { note in
                Label(note, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .lineLimit(8)
                    .textSelection(.enabled)
            }
            if run.directory != nil {
                HStack(spacing: 12) {
                    Button("Open scan log") { model.openScanFile(run, "scan.log") }
                    if run.dependencies == .error { Button("Open dependencies log") { model.openScanFile(run, "deps.log") } }
                    if run.monitor == .error { Button("Open monitor log") { model.openScanFile(run, "monitor.log") } }
                    Button("Show scan folder") { model.openScanFile(run, "") }
                }
                .buttonStyle(.link)
                .font(.caption)
            }
        }
    }
}

enum Clipboard {
    static func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}

struct FindingRow: View {
    let finding: Finding
    var ignoredRule: IgnoreRule? = nil
    var ignore: () -> Void = {}
    var unignore: () -> Void = {}
    var copyDetails: () -> Void = {}
    var copyPrompt: () -> Void = {}
    var copySameType: () -> Void = {}
    var sameTypeCount = 1

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            SeverityTag(severity: finding.severity)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Image(systemName: finding.kind == .dependency ? "shippingbox" : "chevron.left.forwardslash.chevron.right")
                        .foregroundStyle(.secondary)
                    Text(finding.title).font(.body.bold())
                }
                Text(finding.location)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                if let fix = finding.fix {
                    Text(fix).font(.caption).foregroundStyle(.green)
                }
                if !finding.detail.isEmpty {
                    Text(finding.detail).font(.caption).foregroundStyle(.secondary).lineLimit(3)
                }
                if let rule = ignoredRule {
                    Label(ignoreSummary(rule), systemImage: "eye.slash")
                        .font(.caption).foregroundStyle(.orange)
                }
            }
            Spacer()
            if ignoredRule != nil {
                Button("Unignore") { unignore() }
                    .buttonStyle(.borderless)
                    .help("Show this vulnerability in the lists and counts again")
            } else {
                Button { ignore() } label: { Image(systemName: "eye.slash") }
                    .buttonStyle(.borderless)
                    .help("Ignore this vulnerability: not vulnerable, won't fix, or a temporary ignore")
            }
            Menu {
                Button("Copy details") { copyDetails() }
                Button("Copy with a prompt for Claude") { copyPrompt() }
                if sameTypeCount > 1 {
                    Button("Copy prompt for all \(sameTypeCount) of this type") { copySameType() }
                }
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
            .help("Copy this vulnerability, with or without a prompt for Claude")
            if let link = finding.url, let url = URL(string: link) {
                Link(destination: url) {
                    Image(systemName: "arrow.up.right.square")
                }
                .help(finding.kind == .dependency ? "Open in the Snyk vulnerability database" : "Open the CWE page for this weakness")
            }
        }
        .padding(.vertical, 4)
    }

    private func ignoreSummary(_ rule: IgnoreRule) -> String {
        var text = rule.reason.label
        if let expires = rule.expires { text += " until \(expires.formatted(date: .abbreviated, time: .omitted))" }
        if !rule.comment.isEmpty { text += ": \(rule.comment)" }
        return text
    }
}
