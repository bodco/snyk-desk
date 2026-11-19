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
                    ForEach(model.config.repos) { repo in
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

    private var runs: [ScanRun] { model.runs[repo.id] ?? [] }
    private var run: ScanRun? { runs.first { $0.id == runId } ?? runs.first }

    private var findings: [Finding] {
        guard let run else { return [] }
        return run.findings.filter { finding in
            let kindOK: Bool
            switch filter {
            case .all: kindOK = true
            case .dependencies: kindOK = finding.kind == .dependency
            case .code: kindOK = finding.kind == .code
            }
            return kindOK && finding.severity <= minimum
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(repo.name).font(.title2.bold())
                    Text(repo.path).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                }
                Spacer()
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
                }

                RunSummary(run: run)

                if findings.isEmpty {
                    ContentUnavailableView("No vulnerabilities", systemImage: "checkmark.shield",
                                           description: Text("Nothing matches the filters in this scan."))
                } else {
                    List(findings) { finding in
                        FindingRow(finding: finding)
                    }
                    .listStyle(.inset)
                }
            }
        }
        .padding(20)
    }
}

struct RunSummary: View {
    let run: ScanRun

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 16) {
                CountsRow(counts: run.counts)
                Spacer()
                StepStatusLabel(title: "Dependencies", status: run.dependencies)
                StepStatusLabel(title: "Code", status: run.code)
                StepStatusLabel(title: "Monitor", status: run.monitor)
            }
            ForEach(run.notes, id: \.self) { note in
                Label(note, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .lineLimit(4)
                    .textSelection(.enabled)
            }
        }
    }
}

struct FindingRow: View {
    let finding: Finding

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
            }
            Spacer()
            if let link = finding.url, let url = URL(string: link) {
                Link(destination: url) {
                    Image(systemName: "arrow.up.right.square")
                }
                .help("Open in the Snyk vulnerability database")
            }
        }
        .padding(.vertical, 4)
    }
}
