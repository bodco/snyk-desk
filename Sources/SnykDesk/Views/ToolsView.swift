import SwiftUI
import SnykDeskCore

/// The list of build tools with their state and install buttons. Used in onboarding and in Settings.
struct ToolsPanel: View {
    @EnvironmentObject private var model: AppModel
    @State private var pendingRemoval: ToolID?

    private var required: [ToolSpec] { ToolCatalog.all.filter { model.toolNeeds[$0.id] != nil } }
    private var others: [ToolSpec] { ToolCatalog.all.filter { model.toolNeeds[$0.id] == nil } }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if !model.toolsChecked {
                HStack {
                    ProgressView().controlSize(.small)
                    Text("Checking what is installed…")
                }
            } else if model.config.repos.isEmpty {
                Text("Add repositories first, and this list will show what they need.")
                    .foregroundStyle(.secondary)
            } else if required.isEmpty {
                Label("The repositories need no extra tools.", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
            }

            if !required.isEmpty {
                SectionLabel("Needed by your repositories")
                ForEach(required) { spec in ToolRow(spec: spec, needed: true, pendingRemoval: $pendingRemoval) }
            }

            if let install = model.toolInstall {
                ToolProgressView(install: install)
            }

            HStack {
                let missing = model.missingRequiredTools
                if !missing.isEmpty {
                    Button("Install missing (\(missing.count))") { model.installTools(missing) }
                        .buttonStyle(.borderedProminent)
                        .disabled(model.toolInstall != nil)
                }
                Button("Check again") { Task { await model.refreshTools() } }
                    .disabled(model.toolInstall != nil)
            }

            if model.toolNeeds[.commandLineTools] != nil {
                Text("Python projects also need their own packages installed in a virtual environment before Snyk can read them.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            if !others.isEmpty {
                DisclosureGroup("Other tools") {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(others) { spec in ToolRow(spec: spec, needed: false, pendingRemoval: $pendingRemoval) }
                    }
                    .padding(.top, 6)
                }
            }

            Text("Tools are downloaded from their official sites into Snyk Desk's own folder. No admin password is needed, and nothing else on your Mac is changed. If you already have a tool, Snyk Desk uses yours.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .task { await model.refreshTools() }
        .onChange(of: model.config.repos.map(\.path)) { _, _ in Task { await model.refreshTools() } }
        .confirmationDialog("Remove \(pendingRemoval.map { ToolCatalog.spec($0).title } ?? "")?",
                            isPresented: Binding(get: { pendingRemoval != nil }, set: { if !$0 { pendingRemoval = nil } })) {
            Button("Remove", role: .destructive) {
                if let id = pendingRemoval { model.removeTool(id) }
                pendingRemoval = nil
            }
        } message: {
            Text("Only the copy installed by Snyk Desk is deleted. Scans that need it will fail until it is installed again.")
        }
    }
}

private struct SectionLabel: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text).font(.caption.bold()).foregroundStyle(.secondary).textCase(.uppercase)
    }
}

struct ToolRow: View {
    @EnvironmentObject private var model: AppModel
    let spec: ToolSpec
    let needed: Bool
    @Binding var pendingRemoval: ToolID?

    private var status: ToolStatus { model.toolStatus[spec.id] ?? .missing }
    private var busy: Bool { model.toolInstall != nil }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            icon.frame(width: 20)
            VStack(alignment: .leading, spacing: 3) {
                Text(spec.title).font(.headline)
                Text(spec.purpose).font(.caption).foregroundStyle(.secondary)
                if let names = model.toolNeeds[spec.id] {
                    Text("Needed by: \(names.joined(separator: ", "))")
                        .font(.caption).foregroundStyle(.secondary)
                }
                switch status {
                case .found(let path, let version, let managed):
                    Text([managed ? "Installed by Snyk Desk" : "Found on your Mac", version]
                        .filter { !$0.isEmpty }.joined(separator: ", "))
                        .font(.caption).foregroundStyle(.green)
                    Text(path).font(.system(.caption2, design: .monospaced)).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.middle)
                case .missing:
                    if spec.id == .commandLineTools && model.waitingForCommandLineTools {
                        Text("Waiting for the macOS installer to finish…")
                            .font(.caption).foregroundStyle(.orange)
                    } else {
                        Text("Not installed, about \(spec.approxSizeMB) MB")
                            .font(.caption).foregroundStyle(needed ? .orange : .secondary)
                    }
                }
                if let error = model.toolErrors[spec.id] {
                    Text(error).font(.caption).foregroundStyle(.red).textSelection(.enabled)
                }
            }
            Spacer()
            action
        }
    }

    @ViewBuilder private var icon: some View {
        switch status {
        case .found:
            Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
        case .missing:
            Image(systemName: needed ? "exclamationmark.circle.fill" : "circle.dashed")
                .foregroundStyle(needed ? Color.orange : Color.secondary)
        }
    }

    @ViewBuilder private var action: some View {
        switch status {
        case .missing:
            if spec.id == .commandLineTools {
                Button(model.waitingForCommandLineTools ? "Waiting…" : "Open installer") {
                    model.installCommandLineTools()
                }
                .disabled(model.waitingForCommandLineTools)
            } else {
                Button("Install") { model.installTools([spec.id]) }.disabled(busy)
            }
        case .found(_, _, let managed):
            if managed {
                Button("Remove") { pendingRemoval = spec.id }.disabled(busy)
            }
        }
    }
}

struct ToolProgressView: View {
    let install: ToolInstallState

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            ProgressView(value: install.overall) {
                Text("\(install.phase)… (\(min(install.done + 1, install.total)) of \(install.total))")
            }
            Text("\(Int(install.overall * 100))% overall. Keep the window open until it finishes.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding(12)
        .background(Color.accentColor.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
    }
}

/// Shown on a repository's page when its scan needs tools that are missing.
struct MissingToolsBanner: View {
    @EnvironmentObject private var model: AppModel
    let repo: RepoConfig

    var body: some View {
        let missing = model.missingTools(for: repo)
        if !missing.isEmpty {
            VStack(alignment: .leading, spacing: 8) {
                Label("Dependency scans will fail: \(missing.map { ToolCatalog.spec($0).title }.joined(separator: ", ")) missing.",
                      systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                if let install = model.toolInstall {
                    ToolProgressView(install: install)
                } else {
                    Button("Install missing tools") { model.installTools(missing) }
                        .buttonStyle(.borderedProminent)
                }
            }
            .padding(12)
            .background(Color.orange.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
        }
    }
}
