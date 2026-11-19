import SwiftUI
import SnykDeskCore

extension Severity {
    var color: Color {
        switch self {
        case .critical: return Color(red: 0.62, green: 0.08, blue: 0.12)
        case .high: return Color(red: 0.85, green: 0.33, blue: 0.10)
        case .medium: return Color(red: 0.80, green: 0.55, blue: 0.05)
        case .low: return Color.gray
        }
    }
}

struct SeverityBadge: View {
    let severity: Severity
    let count: Int

    var body: some View {
        HStack(spacing: 4) {
            Text(severity.letter)
                .font(.caption.bold())
                .foregroundStyle(Color.white)
                .frame(width: 18, height: 18)
                .background(severity.color.opacity(count == 0 ? 0.35 : 1), in: RoundedRectangle(cornerRadius: 4))
            Text("\(count)")
                .font(.callout.monospacedDigit())
                .foregroundStyle(count == 0 ? Color.secondary : Color.primary)
        }
        .help("\(severity.label): \(count)")
    }
}

struct CountsRow: View {
    let counts: SeverityCounts

    var body: some View {
        HStack(spacing: 10) {
            ForEach(Severity.allCases, id: \.self) { severity in
                SeverityBadge(severity: severity, count: counts[severity])
            }
        }
    }
}

struct SeverityTag: View {
    let severity: Severity

    var body: some View {
        Text(severity.label)
            .font(.caption.bold())
            .foregroundStyle(Color.white)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .frame(minWidth: 64)
            .background(severity.color, in: Capsule())
    }
}

struct StepStatusLabel: View {
    let title: String
    let status: StepStatus
    var count: Int? = nil
    var pick: (() -> Void)? = nil

    private var text: String {
        if let count, status == .issues || count > 0 { return "\(title): \(count) found" }
        return "\(title): \(status.label)"
    }

    var body: some View {
        if let pick, (count ?? 0) > 0 {
            Button(action: pick) { content }
                .buttonStyle(.plain)
                .help("Show these in the list")
        } else {
            content
        }
    }

    private var content: some View {
        HStack(spacing: 4) {
            Image(systemName: icon).foregroundStyle(color)
            Text(text).font(.caption)
        }
    }

    private var icon: String {
        switch status {
        case .clean: return "checkmark.circle.fill"
        case .issues: return "exclamationmark.triangle.fill"
        case .error: return "xmark.octagon.fill"
        case .unsupported: return "minus.circle"
        case .skipped: return "circle.dashed"
        }
    }

    private var color: Color {
        switch status {
        case .clean: return .green
        case .issues: return .orange
        case .error: return .red
        case .unsupported, .skipped: return .secondary
        }
    }
}

struct ScanProgressView: View {
    @EnvironmentObject private var model: AppModel
    let scan: ActiveScan

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text(statusText).font(.callout)
                Spacer()
                Button("Stop") { model.cancelScan() }
            }
            DisclosureGroup("Log") {
                ScrollView {
                    Text(scan.log.joined(separator: "\n"))
                        .font(.system(.caption, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                }
                .frame(height: 120)
            }
        }
        .padding(12)
        .background(Color.accentColor.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
    }

    private var statusText: String {
        let name = scan.currentRepo.flatMap { model.repo($0)?.name } ?? "repositories"
        let position = scan.currentRepo.flatMap { id in scan.repoIds.firstIndex(of: id) }.map { "\($0 + 1)/\(scan.repoIds.count)" } ?? ""
        return "Scanning \(name) \(position): \(scan.step)"
    }
}

struct UsageView: View {
    @EnvironmentObject private var model: AppModel
    let usage: MonthlyUsage
    @State private var syncing = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(usage.calibrated ? "Free plan tests this month" : "Free plan tests this month (local estimate)").font(.headline)
            usageBar("Open Source", used: usage.openSource, limit: usage.openSourceLimit)
            usageBar("Code", used: usage.code, limit: usage.codeLimit)
            Text(usage.calibrated
                 ? "Starts from the numbers you copied from Snyk, plus the scans this app ran since."
                 : "Counted from scans run by this app, so it can differ from Snyk. Sync with Snyk to start from its own numbers.")
                .font(.caption).foregroundStyle(.secondary)
            Button("Sync with Snyk…") { syncing = true }
                .buttonStyle(.link).font(.caption)
        }
        .sheet(isPresented: $syncing) { UsageSyncSheet(usage: usage) }
    }

    private func usageBar(_ title: String, used: Int, limit: Int) -> some View {
        let ratio = min(Double(used) / Double(max(limit, 1)), 1)
        return VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text(title).font(.caption)
                Spacer()
                Text("\(used) / \(limit)").font(.caption.monospacedDigit())
                    .foregroundStyle(ratio >= 0.8 ? Color.orange : Color.secondary)
            }
            ProgressView(value: ratio).tint(ratio >= 0.8 ? Color.orange : Color.accentColor)
        }
    }
}

struct UsageSyncSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let usage: MonthlyUsage
    @State private var osUsed = 0
    @State private var osLimit = 0
    @State private var codeUsed = 0
    @State private var codeLimit = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Sync with Snyk").font(.title3.bold())
            Text("Snyk gives no public way to read the test counter, so copy it once from your organization's Settings, Usage page. From then on this app adds the scans it runs.")
                .font(.callout).foregroundStyle(.secondary)
            Link("Open Snyk", destination: URL(string: "https://app.snyk.io")!)
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 8) {
                GridRow {
                    Text("")
                    Text("Used").font(.caption).foregroundStyle(.secondary)
                    Text("Limit").font(.caption).foregroundStyle(.secondary)
                }
                GridRow {
                    Text("Open Source")
                    TextField("", value: $osUsed, format: .number).frame(width: 80)
                    TextField("", value: $osLimit, format: .number).frame(width: 80)
                }
                GridRow {
                    Text("Code")
                    TextField("", value: $codeUsed, format: .number).frame(width: 80)
                    TextField("", value: $codeLimit, format: .number).frame(width: 80)
                }
            }
            HStack {
                if usage.calibrated {
                    Button("Back to local estimate") { model.clearUsageCalibration(); dismiss() }
                }
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Save") {
                    model.calibrateUsage(openSourceUsed: osUsed, codeUsed: codeUsed, openSourceLimit: osLimit, codeLimit: codeLimit)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(20)
        .frame(width: 420)
        .onAppear {
            osUsed = usage.openSource
            osLimit = usage.openSourceLimit
            codeUsed = usage.code
            codeLimit = usage.codeLimit
        }
    }
}

struct ResultsFolderRow: View {
    @EnvironmentObject private var model: AppModel
    let repo: RepoConfig

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Image(systemName: "tray.full").foregroundStyle(.secondary)
                Text("Scans go to").font(.caption).foregroundStyle(.secondary)
                Text(model.resultsFolder(for: repo))
                    .font(.system(.caption, design: .monospaced))
                    .lineLimit(1).truncationMode(.middle)
                    .textSelection(.enabled)
                Text(repo.resultsFolder == nil ? "(default)" : "(custom)")
                    .font(.caption).foregroundStyle(.secondary)
            }
            HStack(spacing: 12) {
                Button("Choose folder…") { model.chooseResultsFolder(for: repo.id) }
                if repo.resultsFolder != nil {
                    Button("Use default") { model.resetResultsFolder(for: repo.id) }
                        .help(model.defaultResultsFolder(for: repo))
                }
                Button("Show in Finder") { model.revealResults(for: repo) }
            }
            .buttonStyle(.link)
            .font(.caption)
        }
    }
}
