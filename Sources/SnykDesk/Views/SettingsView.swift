import SwiftUI
import SnykDeskCore

struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var pendingRemoval: RepoConfig?

    var body: some View {
        Form {
            Section("Repositories") {
                if model.config.repos.isEmpty {
                    Text("No repositories yet.").foregroundStyle(.secondary)
                }
                ForEach($model.config.repos) { $repo in
                    RepoSettingsRow(repo: $repo) { pendingRemoval = repo }
                }
                Button("Add repositories…") { model.addRepos() }
            }

            Section("Launcher") {
                LauncherStatusView()
                HStack {
                    Button("Change folder…") { _ = model.chooseLauncherFolder() }
                    Button("Show in Finder") { model.revealLauncher() }
                        .disabled(model.launcherStatus != .installed)
                    if model.launcherStatus == .foreign {
                        Button("Replace the existing file") { model.writeLauncher(force: true) }
                    }
                }
            }

            Section("Snyk CLI") {
                CLIStatusView()
            }

            Section("Snyk account") {
                AuthStatusView()
            }

            Section("This month") {
                UsageView(usage: model.usage)
            }

            Section("Results") {
                Text("Scan results are kept in ~/Library/Application Support/SnykDesk/results, one folder per repository and scan.")
                    .font(.caption).foregroundStyle(.secondary)
                Button("Run setup again") { model.restartOnboarding() }
            }
        }
        .formStyle(.grouped)
        .confirmationDialog("Remove \(pendingRemoval?.name ?? "")?",
                            isPresented: Binding(get: { pendingRemoval != nil }, set: { if !$0 { pendingRemoval = nil } })) {
            Button("Remove", role: .destructive) {
                if let repo = pendingRemoval { model.removeRepo(repo.id) }
                pendingRemoval = nil
            }
        } message: {
            Text("The folder and its past results stay on disk. It is only removed from Snyk Desk.")
        }
    }
}

struct RepoSettingsRow: View {
    @Binding var repo: RepoConfig
    let onRemove: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                TextField("Name", text: $repo.name).textFieldStyle(.plain).font(.headline)
                Spacer()
                Button(role: .destructive, action: onRemove) {
                    Image(systemName: "trash")
                }
                .buttonStyle(.borderless)
                .help("Remove from Snyk Desk")
            }
            Text(repo.path).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            if !FileManager.default.fileExists(atPath: repo.path) {
                Label("Folder not found", systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange)
            }
            HStack(spacing: 14) {
                Toggle("Dependencies", isOn: $repo.scanDependencies)
                Toggle("Code", isOn: $repo.scanCode)
                Toggle("Monitor", isOn: $repo.monitor)
                Toggle("In schedule", isOn: $repo.scheduled)
            }
            .toggleStyle(.checkbox)
            .font(.caption)
        }
        .padding(.vertical, 4)
    }
}

struct LauncherStatusView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        if let folder = model.config.launcherFolder {
            VStack(alignment: .leading, spacing: 4) {
                Text(LauncherGenerator.url(in: folder).path)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                switch model.launcherStatus {
                case .installed:
                    Label("Launcher installed and up to date", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                case .missing:
                    Label("Launcher not written yet", systemImage: "circle.dashed")
                        .foregroundStyle(.secondary)
                case .foreign:
                    Label("A different file named \(Paths.launcherName) is in this folder", systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                }
            }
        } else {
            Text("No folder chosen yet.").foregroundStyle(.secondary)
        }
    }
}

struct CLIStatusView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            switch model.cli {
            case .checking:
                HStack {
                    ProgressView().controlSize(.small)
                    Text("Looking for the Snyk CLI…")
                }
            case .installed(let path, let version):
                Label("Snyk CLI \(version) is installed", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                Text(path).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
            case .missing:
                Label("Snyk CLI not found", systemImage: "xmark.circle")
                    .foregroundStyle(.secondary)
            }
            if let progress = model.installProgress {
                ProgressView(value: progress) {
                    Text("Downloading the Snyk CLI… \(Int(progress * 100))%")
                }
            }
            if let error = model.installError {
                Text(error).font(.caption).foregroundStyle(.red)
            }
            HStack {
                if model.cli == .missing {
                    Button("Install Snyk CLI") { model.installCLI() }
                        .buttonStyle(.borderedProminent)
                        .disabled(model.installProgress != nil)
                }
                Button("Check again") { Task { await model.detectCLI() } }
                    .disabled(model.installProgress != nil)
            }
        }
    }
}

struct AuthStatusView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            switch model.auth {
            case .unknown, .checking:
                HStack {
                    ProgressView().controlSize(.small)
                    Text("Checking the login…")
                }
            case .loggingIn:
                HStack {
                    ProgressView().controlSize(.small)
                    Text("Finish the login in your browser…")
                }
            case .loggedIn(let user):
                Label("Logged in as \(user)", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
            case .loggedOut:
                Label("Not logged in", systemImage: "person.crop.circle.badge.xmark")
                    .foregroundStyle(.secondary)
            }
            HStack {
                Button(model.isLoggedIn ? "Log in again" : "Log in to Snyk") { model.login() }
                    .buttonStyle(.borderedProminent)
                    .disabled(model.snykPath == nil || model.auth == .loggingIn)
                Button("Check again") { Task { await model.checkAuth() } }
                    .disabled(model.snykPath == nil)
            }
            Text("Login opens snyk.io in your browser. The Snyk CLI keeps the token, Snyk Desk never reads or stores it.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }
}
