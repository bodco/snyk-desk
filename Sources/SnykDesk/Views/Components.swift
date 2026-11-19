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
    let usage: MonthlyUsage

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Free plan tests this month (local estimate)").font(.headline)
            usageBar("Open Source", used: usage.openSource, limit: MonthlyUsage.openSourceLimit)
            usageBar("Code", used: usage.code, limit: MonthlyUsage.codeLimit)
            Text("Counted from scans run by this app. Snyk keeps the official count.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private func usageBar(_ title: String, used: Int, limit: Int) -> some View {
        let ratio = min(Double(used) / Double(limit), 1)
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
