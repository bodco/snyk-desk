import SwiftUI
import SnykDeskCore

struct OnboardingView: View {
    @EnvironmentObject private var model: AppModel
    @State private var step = 0

    private let titles = ["Launcher", "Snyk CLI", "Repositories", "Snyk account"]

    private var canContinue: Bool {
        switch step {
        case 0: return model.config.launcherFolder != nil && model.launcherStatus == .installed
        case 1: return model.snykPath != nil
        case 2: return !model.config.repos.isEmpty
        default: return model.isLoggedIn
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            VStack(spacing: 6) {
                Text("Set up Snyk Desk").font(.title.bold())
                HStack(spacing: 24) {
                    ForEach(0..<titles.count, id: \.self) { index in
                        StepMarker(index: index, title: titles[index], current: step)
                    }
                }
            }
            .padding(20)

            Divider()

            Group {
                switch step {
                case 0: LauncherStep()
                case 1: CLIStep()
                case 2: ReposStep()
                default: LoginStep()
                }
            }
            .frame(maxWidth: 620, maxHeight: .infinity, alignment: .topLeading)
            .padding(32)

            Divider()

            HStack {
                if step > 0 {
                    Button("Back") { step -= 1 }
                }
                Spacer()
                if step == titles.count - 1 && !model.isLoggedIn {
                    Button("Skip for now") { finish() }
                }
                Button(step == titles.count - 1 ? "Finish" : "Continue") {
                    if step == titles.count - 1 { finish() } else { step += 1 }
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
                .disabled(!canContinue)
            }
            .padding(16)
        }
    }

    private func finish() {
        model.config.onboardingDone = true
        model.writeLauncher()
    }
}

struct StepMarker: View {
    let index: Int
    let title: String
    let current: Int

    var body: some View {
        HStack(spacing: 6) {
            ZStack {
                Circle()
                    .fill(index <= current ? Color.accentColor : Color.secondary.opacity(0.25))
                    .frame(width: 22, height: 22)
                if index < current {
                    Image(systemName: "checkmark").font(.caption.bold()).foregroundStyle(Color.white)
                } else {
                    Text("\(index + 1)").font(.caption.bold()).foregroundStyle(Color.white)
                }
            }
            Text(title).foregroundStyle(index == current ? Color.primary : Color.secondary)
        }
    }
}

struct LauncherStep: View {
    @EnvironmentObject private var model: AppModel
    @State private var found: LauncherStatus?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Where should the scan launcher live?").font(.title2.bold())
            Text("The launcher is a small script, \(Paths.launcherName), that runs the Snyk CLI for each repository. The app and the schedule both use it, and you can run it from Terminal too. Scans are saved next to it as <project>/<repository>/<date-time>, unless you pick another folder for a repository later.")
                .foregroundStyle(.secondary)
            Button("Choose folder…") { found = model.chooseLauncherFolder() }
                .buttonStyle(.borderedProminent)
            if model.config.launcherFolder != nil {
                LauncherStatusView()
                if found == .installed {
                    Text("A launcher was already in this folder. It is kept and updated with your settings.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if model.launcherStatus == .foreign {
                    Button("Replace the existing file") { model.writeLauncher(force: true) }
                }
            }
        }
    }
}

struct CLIStep: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Snyk CLI").font(.title2.bold())
            Text("Snyk Desk drives the official Snyk CLI. If it is not installed, the app downloads the standalone binary into its own folder. Node.js is not needed for that.")
                .foregroundStyle(.secondary)
            CLIStatusView()
        }
    }
}

struct ReposStep: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Which repositories should be scanned?").font(.title2.bold())
            Text("Pick local folders. The project is guessed from the path (for example .../bink/repos/api belongs to bink), and you can change it in Settings. You can also add or remove repositories there and choose per repository what to scan.")
                .foregroundStyle(.secondary)
            Button("Add repositories…") { model.addRepos() }
                .buttonStyle(.borderedProminent)
            if !model.config.repos.isEmpty {
                List {
                    ForEach(model.config.repos) { repo in
                        HStack {
                            VStack(alignment: .leading) {
                                Text("\(repo.project) / \(repo.name)")
                                Text(repo.path).font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button {
                                model.removeRepo(repo.id)
                            } label: {
                                Image(systemName: "minus.circle")
                            }
                            .buttonStyle(.borderless)
                        }
                    }
                }
                .frame(minHeight: 160)
            }
            Text("By default each repository gets a dependency scan, a code scan and a snapshot in your Snyk dashboard. A code scan uploads the source code to Snyk for analysis.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }
}

struct LoginStep: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Log in to Snyk").font(.title2.bold())
            Text("The Snyk CLI needs your account to run tests. A free account works. It has monthly test limits; when they run out, tests stop until the next month.")
                .foregroundStyle(.secondary)
            AuthStatusView()
        }
    }
}
