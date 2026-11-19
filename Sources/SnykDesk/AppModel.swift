import AppKit
import SwiftUI
import SnykDeskCore

enum CLIState: Equatable {
    case checking
    case missing
    case installed(path: String, version: String)
}

enum AuthState: Equatable {
    case unknown
    case checking
    case loggedOut
    case loggingIn
    case loggedIn(String)
}

struct ActiveScan: Equatable {
    var repoIds: [UUID]
    var currentRepo: UUID?
    var step: String
    var log: [String]
}

@MainActor
final class AppModel: ObservableObject {
    @Published var config: AppConfig {
        didSet {
            if config != oldValue { persist() }
        }
    }
    @Published private(set) var runs: [UUID: [ScanRun]] = [:]
    @Published private(set) var cli: CLIState = .checking
    @Published private(set) var auth: AuthState = .unknown
    @Published private(set) var installProgress: Double?
    @Published private(set) var installError: String?
    @Published private(set) var activeScan: ActiveScan?
    @Published var toolStatus: [ToolID: ToolStatus] = [:]
    @Published var toolNeeds: [ToolID: [String]] = [:]
    @Published var repoNeeds: [UUID: Set<ToolID>] = [:]
    @Published var toolInstall: ToolInstallState?
    @Published var toolErrors: [ToolID: String] = [:]
    @Published var waitingForCommandLineTools = false
    @Published var toolsChecked = false
    @Published var scheduleMessage: String?
    @Published var lastError: String?

    var pathEnv: String = Shell.merge([], Shell.commonDirs)
    private var scanProcess: Process?
    private var downloader: CLIDownloader?

    init() {
        config = ConfigStore.load()
        reloadRuns()
        Task { await refreshEnvironment() }
    }

    // MARK: Persistence and launcher

    private func persist() {
        do {
            try ConfigStore.save(config)
        } catch {
            lastError = "Could not save settings: \(error.localizedDescription)"
        }
        writeLauncher()
    }

    var launcherURL: URL? {
        config.launcherFolder.map { LauncherGenerator.url(in: $0) }
    }

    var launcherStatus: LauncherStatus {
        guard let folder = config.launcherFolder else { return .missing }
        return LauncherGenerator.status(in: folder)
    }

    /// Rewrites the launcher with the current settings. A foreign file with the same name is left alone unless forced.
    func writeLauncher(force: Bool = false) {
        guard let folder = config.launcherFolder else { return }
        if !force && LauncherGenerator.status(in: folder) == .foreign { return }
        do {
            try LauncherGenerator.install(config: config, folder: folder,
                                          snykPath: config.snykPath ?? "snyk", pathEnv: pathEnv,
                                          javaHome: ToolCatalog.managedJavaHome())
        } catch {
            lastError = "Could not write the launcher: \(error.localizedDescription)"
            AppLog.write("launcher write failed: \(error.localizedDescription)")
        }
    }

    /// Returns the folder's state before anything was written.
    @discardableResult
    func setLauncherFolder(_ path: String) -> LauncherStatus {
        let before = LauncherGenerator.status(in: path)
        config.launcherFolder = path
        if before != .foreign { writeLauncher() }
        reloadRuns()
        return before
    }

    func chooseLauncherFolder() -> LauncherStatus? {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.prompt = "Use this folder"
        panel.message = "Choose where to keep the scan launcher (snyk-desk-scan.sh)."
        guard panel.runModal() == .OK, let url = panel.url else { return nil }
        return setLauncherFolder(url.path)
    }

    func revealLauncher() {
        if let url = launcherURL { NSWorkspace.shared.activateFileViewerSelecting([url]) }
    }

    // MARK: Environment, CLI, account

    func refreshEnvironment() async {
        pathEnv = await Task.detached { Shell.userPATH() }.value
        await detectCLI()
        await checkAuth()
        writeLauncher()
        await refreshTools()
    }

    func environment() -> [String: String] { Shell.environment(path: pathEnv) }

    func detectCLI() async {
        cli = .checking
        let path = pathEnv
        let configured = config.snykPath
        let env = environment()
        let found: (String, String)? = await Task.detached {
            var candidates: [String] = []
            if let configured { candidates.append(configured) }
            if let onPath = Shell.find("snyk", in: path) { candidates.append(onPath) }
            for candidate in candidates where FileManager.default.isExecutableFile(atPath: candidate) {
                let result = Shell.run(candidate, ["--version"], environment: env)
                if result.status == 0 {
                    let version = result.output.split(separator: "\n").last.map(String.init) ?? ""
                    return (candidate, version.trimmingCharacters(in: .whitespaces))
                }
            }
            return nil
        }.value
        if let found {
            cli = .installed(path: found.0, version: found.1)
            if config.snykPath != found.0 { config.snykPath = found.0 }
        } else {
            cli = .missing
        }
    }

    var snykPath: String? {
        if case .installed(let path, _) = cli { return path }
        return nil
    }

    func installCLI() {
        guard installProgress == nil else { return }
        installError = nil
        installProgress = 0
        let downloader = CLIDownloader(
            onProgress: { [weak self] value in
                Task { @MainActor in self?.installProgress = value }
            },
            onFinish: { [weak self] result in
                Task { @MainActor in
                    guard let self else { return }
                    self.installProgress = nil
                    self.downloader = nil
                    switch result {
                    case .success(let url):
                        self.config.snykPath = url.path
                        await self.detectCLI()
                        await self.checkAuth()
                    case .failure(let error):
                        self.installError = error.localizedDescription
                    }
                }
            })
        self.downloader = downloader
        downloader.start()
    }

    func checkAuth() async {
        guard let snyk = snykPath else {
            auth = .loggedOut
            return
        }
        auth = .checking
        let env = environment()
        let result = await Task.detached {
            Shell.run(snyk, ["whoami", "--experimental"], environment: env)
        }.value
        let user = result.output.split(separator: "\n").last.map(String.init)?
            .trimmingCharacters(in: .whitespaces) ?? ""
        auth = (result.status == 0 && !user.isEmpty) ? .loggedIn(user) : .loggedOut
    }

    func login() {
        guard let snyk = snykPath else { return }
        auth = .loggingIn
        let env = environment()
        Task {
            let result = await Task.detached { Shell.run(snyk, ["auth"], environment: env) }.value
            if result.status != 0 {
                lastError = "Snyk login did not finish: \(result.output.trimmingCharacters(in: .whitespacesAndNewlines))"
            }
            await checkAuth()
        }
    }

    var isLoggedIn: Bool {
        if case .loggedIn = auth { return true }
        return false
    }

    // MARK: Repositories

    func addRepos() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = true
        panel.prompt = "Add"
        panel.message = "Choose one or more local repository folders."
        guard panel.runModal() == .OK else { return }
        var repos = config.repos
        for url in panel.urls where !repos.contains(where: { $0.path == url.path }) {
            repos.append(RepoConfig(name: url.lastPathComponent, path: url.path))
        }
        config.repos = repos
    }

    func removeRepo(_ id: UUID) {
        config.repos.removeAll { $0.id == id }
        runs[id] = nil
    }

    func repo(_ id: UUID) -> RepoConfig? { config.repos.first { $0.id == id } }

    /// Project names in the order their first repository was added.
    var projects: [String] {
        var names: [String] = []
        for repo in config.repos where !names.contains(repo.project) { names.append(repo.project) }
        return names
    }

    func repos(in project: String) -> [RepoConfig] {
        config.repos.filter { $0.project == project }
    }

    func projectCounts(_ project: String) -> SeverityCounts {
        repos(in: project).compactMap { latestRun($0.id)?.counts }.reduce(SeverityCounts(), +)
    }

    func scanProject(_ project: String) {
        scan(repos(in: project).map(\.id))
    }

    // MARK: Results folders

    func resultsFolder(for repo: RepoConfig) -> String {
        ResultsLocation.folder(for: repo, config: config)
    }

    func defaultResultsFolder(for repo: RepoConfig) -> String {
        ResultsLocation.defaultFolder(for: repo, config: config)
    }

    func chooseResultsFolder(for id: UUID) {
        guard let index = config.repos.firstIndex(where: { $0.id == id }) else { return }
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.prompt = "Use this folder"
        panel.message = "Choose where to keep the scans of \(config.repos[index].name)."
        panel.directoryURL = URL(fileURLWithPath: resultsFolder(for: config.repos[index]))
        guard panel.runModal() == .OK, let url = panel.url else { return }
        config.repos[index].resultsFolder = url.path
        reloadRuns()
    }

    func resetResultsFolder(for id: UUID) {
        guard let index = config.repos.firstIndex(where: { $0.id == id }) else { return }
        config.repos[index].resultsFolder = nil
        reloadRuns()
    }

    func revealResults(for repo: RepoConfig) {
        let url = URL(fileURLWithPath: resultsFolder(for: repo), isDirectory: true)
        Paths.ensure(url)
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }

    // MARK: Results

    func reloadRuns() {
        var all: [UUID: [ScanRun]] = [:]
        for repo in config.repos {
            all[repo.id] = ResultParser.loadRuns(repo: repo, config: config)
        }
        runs = all
    }

    func latestRun(_ id: UUID) -> ScanRun? { runs[id]?.first }

    var totalCounts: SeverityCounts {
        config.repos.compactMap { latestRun($0.id)?.counts }.reduce(SeverityCounts(), +)
    }

    var hasAnyRun: Bool { config.repos.contains { latestRun($0.id) != nil } }

    var usage: MonthlyUsage {
        UsageCalculator.thisMonth(runs.values.flatMap { $0 })
    }

    // MARK: Scanning

    func scan(_ ids: [UUID]) {
        guard activeScan == nil, !ids.isEmpty else { return }
        guard config.launcherFolder != nil else {
            lastError = "Choose a launcher folder in Settings first."
            return
        }
        writeLauncher()
        guard let launcher = launcherURL, launcherStatus == .installed else {
            lastError = "The launcher is missing or a different file has its name. Check Settings."
            return
        }
        activeScan = ActiveScan(repoIds: ids, currentRepo: nil, step: "Starting", log: [])
        AppLog.write("scan started: \(ids.count) repo(s), launcher \(launcher.path)")

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = [launcher.path] + ids.map(\.uuidString)
        process.environment = environment()
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }
            let text = String(decoding: data, as: UTF8.self)
            Task { @MainActor in self?.handleOutput(text) }
        }
        process.terminationHandler = { [weak self] _ in
            pipe.fileHandleForReading.readabilityHandler = nil
            Task { @MainActor in
                AppLog.write("scan finished")
                self?.activeScan = nil
                self?.scanProcess = nil
                self?.reloadRuns()
            }
        }
        do {
            try process.run()
            scanProcess = process
        } catch {
            activeScan = nil
            lastError = "Could not start the scan: \(error.localizedDescription)"
            AppLog.write("scan could not start: \(error.localizedDescription)")
        }
    }

    func openAppLog() {
        Paths.ensure(Paths.logs)
        if !FileManager.default.fileExists(atPath: AppLog.file.path) { AppLog.write("log opened") }
        NSWorkspace.shared.open(AppLog.file)
    }

    func openScanFile(_ run: ScanRun, _ name: String) {
        guard let dir = run.directory else { return }
        let file = dir.appendingPathComponent(name)
        if FileManager.default.fileExists(atPath: file.path) {
            NSWorkspace.shared.open(file)
        } else {
            NSWorkspace.shared.activateFileViewerSelecting([dir])
        }
    }

    func cancelScan() {
        scanProcess?.terminate()
    }

    private func handleOutput(_ text: String) {
        guard var scan = activeScan else { return }
        for raw in text.split(separator: "\n") {
            let line = String(raw)
            scan.log.append(line)
            AppLog.write("launcher: \(line)")
            let parts = line.split(separator: " ").map(String.init)
            guard let head = parts.first else { continue }
            switch head {
            case "::repo":
                if parts.count > 1 { scan.currentRepo = UUID(uuidString: parts[1]) }
                scan.step = "Starting"
            case "::step":
                scan.step = parts.count > 1 ? stepLabel(parts[1]) : scan.step
            case "::done":
                if parts.count > 1, let id = UUID(uuidString: parts[1]), let repo = repo(id) {
                    runs[id] = ResultParser.loadRuns(repo: repo, config: config)
                }
            default:
                break
            }
        }
        if scan.log.count > 300 { scan.log.removeFirst(scan.log.count - 300) }
        activeScan = scan
    }

    private func stepLabel(_ step: String) -> String {
        switch step {
        case "deps": return "Dependencies (snyk test)"
        case "code": return "Code (snyk code test)"
        case "monitor": return "Snapshot (snyk monitor)"
        default: return step
        }
    }

    // MARK: Schedule

    var scheduleInstalled: Bool { ScheduleWriter.isInstalled }

    func applySchedule() {
        writeLauncher()
        do {
            if config.schedule.enabled {
                guard let launcher = launcherURL, launcherStatus == .installed else {
                    throw DeskError("Install the launcher first (Settings, Launcher).")
                }
                try ScheduleWriter.install(launcher: launcher.path, schedule: config.schedule)
                if let next = ScheduleWriter.nextRun(config.schedule) {
                    scheduleMessage = "Schedule is on. Next scan: \(next.formatted(date: .abbreviated, time: .shortened))."
                } else {
                    scheduleMessage = "Schedule is on."
                }
            } else {
                ScheduleWriter.uninstall()
                scheduleMessage = "Schedule is off."
            }
        } catch {
            scheduleMessage = error.localizedDescription
        }
        objectWillChange.send()
    }

    func restartOnboarding() {
        config.onboardingDone = false
    }
}

/// Downloads the standalone Snyk CLI binary into Application Support, with progress.
final class CLIDownloader: NSObject, URLSessionDownloadDelegate {
    private let onProgress: (Double) -> Void
    private let onFinish: (Result<URL, Error>) -> Void
    private var session: URLSession?
    private var sources: [URL]
    private var finished = false

    init(onProgress: @escaping (Double) -> Void, onFinish: @escaping (Result<URL, Error>) -> Void) {
        self.onProgress = onProgress
        self.onFinish = onFinish
        #if arch(arm64)
        let file = "snyk-macos-arm64"
        #else
        let file = "snyk-macos"
        #endif
        self.sources = [
            URL(string: "https://downloads.snyk.io/cli/stable/\(file)")!,
            URL(string: "https://static.snyk.io/cli/latest/\(file)")!
        ]
        super.init()
    }

    func start() {
        guard !sources.isEmpty else {
            finish(.failure(DeskError("Could not download the Snyk CLI. Install it with `npm install -g snyk` and press Check again.")))
            return
        }
        let url = sources.removeFirst()
        let session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
        self.session = session
        session.downloadTask(with: url).resume()
    }

    private func finish(_ result: Result<URL, Error>) {
        guard !finished else { return }
        finished = true
        session?.finishTasksAndInvalidate()
        onFinish(result)
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didWriteData bytesWritten: Int64,
                    totalBytesWritten: Int64, totalBytesExpectedToWrite: Int64) {
        guard totalBytesExpectedToWrite > 0 else { return }
        onProgress(Double(totalBytesWritten) / Double(totalBytesExpectedToWrite))
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didFinishDownloadingTo location: URL) {
        let status = (downloadTask.response as? HTTPURLResponse)?.statusCode ?? 0
        guard status == 200 else {
            session.invalidateAndCancel()
            start()
            return
        }
        let destination = Paths.bin.appendingPathComponent("snyk")
        do {
            Paths.ensure(Paths.bin)
            try? FileManager.default.removeItem(at: destination)
            try FileManager.default.moveItem(at: location, to: destination)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: destination.path)
            finish(.success(destination))
        } catch {
            finish(.failure(error))
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        guard let error else { return }
        if (error as NSError).code == NSURLErrorCancelled { return }
        if sources.isEmpty {
            finish(.failure(error))
        } else {
            start()
        }
    }
}
