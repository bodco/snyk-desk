import SwiftUI
import SnykDeskCore

struct DashboardView: View {
    @EnvironmentObject private var model: AppModel
    let openRepo: (UUID) -> Void

    var body: some View {
        if model.config.repos.isEmpty {
            ContentUnavailableView {
                Label("No repositories yet", systemImage: "folder.badge.plus")
            } description: {
                Text("Add the local folders of the repositories you want to scan.")
            } actions: {
                Button("Add repositories…") { model.addRepos() }
                    .buttonStyle(.borderedProminent)
            }
        } else {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    header
                    if let scan = model.activeScan {
                        ScanProgressView(scan: scan)
                    }
                    DashboardToolsBanner()
                    if !model.hasAnyRun && model.activeScan == nil {
                        notScannedBanner
                    }
                    HStack(alignment: .top, spacing: 20) {
                        UsageView(usage: model.usage)
                            .frame(maxWidth: 360)
                        Spacer()
                    }
                    ForEach(model.projects, id: \.self) { project in
                        VStack(alignment: .leading, spacing: 10) {
                            HStack(spacing: 12) {
                                Text(project).font(.title3.bold())
                                Text("\(model.repos(in: project).count) repositories")
                                    .font(.caption).foregroundStyle(.secondary)
                                Spacer()
                                CountsRow(counts: model.projectCounts(project))
                                Button("Scan project") { model.scanProject(project) }
                                    .disabled(model.activeScan != nil)
                            }
                            LazyVGrid(columns: [GridItem(.adaptive(minimum: 270), spacing: 16)], spacing: 16) {
                                ForEach(model.repos(in: project)) { repo in
                                    RepoCard(repo: repo, run: model.latestRun(repo.id)) { openRepo(repo.id) }
                                }
                            }
                        }
                    }
                }
                .padding(24)
            }
        }
    }

    private var header: some View {
        HStack(alignment: .center) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Dashboard").font(.largeTitle.bold())
                Text("Latest scan of each repository, by project").foregroundStyle(.secondary)
            }
            Spacer()
            CountsRow(counts: model.totalCounts)
            Button {
                model.scan(model.config.repos.map(\.id))
            } label: {
                Label("Scan all", systemImage: "play.fill")
            }
            .buttonStyle(.borderedProminent)
            .disabled(model.activeScan != nil)
            .padding(.leading, 12)
        }
    }

    private var notScannedBanner: some View {
        HStack(spacing: 12) {
            Image(systemName: "shield").font(.title2).foregroundStyle(.secondary)
            VStack(alignment: .leading) {
                Text("Nothing scanned yet").font(.headline)
                Text("Press Scan all, or scan one repository from its card.").foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(16)
        .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
    }
}

struct RepoCard: View {
    @EnvironmentObject private var model: AppModel
    let repo: RepoConfig
    let run: ScanRun?
    let open: () -> Void

    private var isScanning: Bool { model.activeScan?.currentRepo == repo.id }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(repo.name).font(.headline).lineLimit(1)
                Spacer()
                if isScanning { ProgressView().controlSize(.small) }
            }
            Text(repo.path)
                .font(.caption).foregroundStyle(.secondary)
                .lineLimit(1).truncationMode(.middle)
            if let run {
                CountsRow(counts: run.counts)
                Text("Scanned \(run.date.formatted(.relative(presentation: .named)))")
                    .font(.caption).foregroundStyle(.secondary)
                if !run.notes.isEmpty {
                    Label("Some steps had problems", systemImage: "exclamationmark.triangle")
                        .font(.caption).foregroundStyle(.orange)
                }
            } else {
                Text("Not scanned yet").foregroundStyle(.secondary)
            }
            HStack {
                Button("Details", action: open)
                Spacer()
                Button("Scan") { model.scan([repo.id]) }
                    .disabled(model.activeScan != nil)
            }
        }
        .padding(14)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.secondary.opacity(0.2)))
    }
}

/// Tells the user, before they scan, that some repositories need build tools that are not installed.
struct DashboardToolsBanner: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        let missing = model.missingRequiredTools
        if !missing.isEmpty || model.toolInstall != nil {
            VStack(alignment: .leading, spacing: 8) {
                if let install = model.toolInstall {
                    ToolProgressView(install: install)
                } else {
                    Label("Some repositories need tools that are not installed: \(missing.map { ToolCatalog.spec($0).title }.joined(separator: ", ")). Their dependency scans would fail.",
                          systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                    Button("Install missing tools") { model.installTools(missing) }
                        .buttonStyle(.borderedProminent)
                }
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.orange.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
        }
    }
}
