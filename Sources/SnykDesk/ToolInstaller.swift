import Foundation
import SnykDeskCore

/// Downloads a file with progress, trying each address in turn.
final class FileDownloader: NSObject, URLSessionDownloadDelegate {
    private var continuation: CheckedContinuation<URL, Error>?
    private var session: URLSession?
    private let onProgress: (Double) -> Void

    private init(onProgress: @escaping (Double) -> Void) {
        self.onProgress = onProgress
    }

    static func download(urls: [String], onProgress: @escaping (Double) -> Void) async throws -> URL {
        var lastError: Error = DeskError("There is no download address for this tool.")
        for text in urls {
            guard let url = URL(string: text) else { continue }
            do {
                return try await FileDownloader(onProgress: onProgress).fetch(url)
            } catch {
                lastError = error
            }
        }
        throw lastError
    }

    private func fetch(_ url: URL) async throws -> URL {
        try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            let session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
            self.session = session
            session.downloadTask(with: url).resume()
        }
    }

    private func complete(_ result: Result<URL, Error>) {
        guard let continuation else { return }
        self.continuation = nil
        session?.finishTasksAndInvalidate()
        continuation.resume(with: result)
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didWriteData bytesWritten: Int64,
                    totalBytesWritten: Int64, totalBytesExpectedToWrite: Int64) {
        guard totalBytesExpectedToWrite > 0 else { return }
        onProgress(Double(totalBytesWritten) / Double(totalBytesExpectedToWrite))
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didFinishDownloadingTo location: URL) {
        let status = (downloadTask.response as? HTTPURLResponse)?.statusCode ?? 0
        guard status == 200 else {
            let host = downloadTask.originalRequest?.url?.host ?? "the download server"
            complete(.failure(DeskError("\(host) answered with status \(status).")))
            return
        }
        let kept = FileManager.default.temporaryDirectory
            .appendingPathComponent("snykdesk-\(UUID().uuidString)")
        do {
            try FileManager.default.moveItem(at: location, to: kept)
            complete(.success(kept))
        } catch {
            complete(.failure(error))
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error { complete(.failure(error)) }
    }
}

struct ToolInstallState: Equatable {
    var queue: [ToolID]
    var current: ToolID?
    /// Progress of the tool being installed, 0 to 1.
    var fraction: Double
    var phase: String
    var done: Int

    var total: Int { queue.count }
    var overall: Double { total == 0 ? 0 : min(1, (Double(done) + fraction) / Double(total)) }
}

extension AppModel {
    // MARK: Status

    func refreshTools() async {
        let path = pathEnv
        let repos = config.repos
        let result = await Task.detached { () -> ([ToolID: ToolStatus], [UUID: Set<ToolID>]) in
            var statuses: [ToolID: ToolStatus] = [:]
            for spec in ToolCatalog.all { statuses[spec.id] = ToolDetector.detect(spec, path: path) }
            var perRepo: [UUID: Set<ToolID>] = [:]
            for repo in repos where repo.scanDependencies || repo.monitor {
                perRepo[repo.id] = RepoRequirements.needs(path: repo.path)
            }
            return (statuses, perRepo)
        }.value
        toolStatus = result.0
        repoNeeds = result.1
        var needs: [ToolID: [String]] = [:]
        for repo in repos {
            for tool in result.1[repo.id] ?? [] { needs[tool, default: []].append(repo.name) }
        }
        toolNeeds = needs
        toolsChecked = true
    }

    /// Tools the configured repositories need and that are not there yet, in catalog order.
    var missingRequiredTools: [ToolID] {
        ToolCatalog.all.map(\.id).filter { toolNeeds[$0] != nil && toolStatus[$0]?.isFound != true }
    }

    func missingTools(for repo: RepoConfig) -> [ToolID] {
        let needed = repoNeeds[repo.id] ?? []
        return ToolCatalog.all.map(\.id).filter { needed.contains($0) && toolStatus[$0]?.isFound != true }
    }

    private func reloadPath() async {
        pathEnv = await Task.detached { Shell.userPATH() }.value
        writeLauncher()
    }

    // MARK: Install

    /// Installs the given tools one after another. Java comes along with Maven and Gradle.
    func installTools(_ requested: [ToolID]) {
        guard toolInstall == nil else { return }
        var wanted = Set(requested)
        if (wanted.contains(.maven) || wanted.contains(.gradle)) && toolStatus[.java]?.isFound != true {
            wanted.insert(.java)
        }
        if wanted.contains(.commandLineTools), toolStatus[.commandLineTools]?.isFound != true {
            installCommandLineTools()
        }
        let queue = ToolCatalog.all.map(\.id).filter {
            wanted.contains($0) && ToolCatalog.spec($0).install != .system && toolStatus[$0]?.isFound != true
        }
        guard !queue.isEmpty else { return }
        for id in queue { toolErrors[id] = nil }
        toolInstall = ToolInstallState(queue: queue, current: nil, fraction: 0, phase: "Starting", done: 0)

        Task {
            for id in queue {
                await installOne(id)
                toolInstall?.done += 1
            }
            await reloadPath()
            await refreshTools()
            toolInstall = nil
        }
    }

    private func installOne(_ id: ToolID) async {
        let spec = ToolCatalog.spec(id)
        guard case .download(let kind, let urls) = spec.install else { return }
        toolInstall?.current = id
        toolInstall?.fraction = 0
        toolInstall?.phase = "Downloading \(spec.title)"
        do {
            let archive = try await FileDownloader.download(urls: urls) { [weak self] value in
                Task { @MainActor in self?.toolInstall?.fraction = value * 0.9 }
            }
            defer { try? FileManager.default.removeItem(at: archive) }
            toolInstall?.phase = "Unpacking \(spec.title)"
            toolInstall?.fraction = 0.92
            let destination = ToolCatalog.managedDir(id)
            try await Task.detached { try ToolUnpacker.unpack(archive: archive, kind: kind, into: destination) }.value
            guard ToolCatalog.isManagedInstalled(id) else {
                throw DeskError("\(spec.title) was unpacked, but \(spec.command) was not found inside it.")
            }
            toolInstall?.fraction = 1
        } catch {
            toolErrors[id] = error.localizedDescription
        }
    }

    /// Opens the macOS installer for the Command Line Tools and waits until it finishes.
    func installCommandLineTools() {
        guard !waitingForCommandLineTools else { return }
        waitingForCommandLineTools = true
        toolErrors[.commandLineTools] = nil
        Task.detached { _ = Shell.run("/usr/bin/xcode-select", ["--install"]) }
        Task {
            let spec = ToolCatalog.spec(.commandLineTools)
            for _ in 0..<600 {
                try? await Task.sleep(nanoseconds: 3_000_000_000)
                let status = await Task.detached { ToolDetector.detect(spec, path: "") }.value
                if status.isFound {
                    toolStatus[.commandLineTools] = status
                    await refreshTools()
                    break
                }
            }
            waitingForCommandLineTools = false
        }
    }

    func removeTool(_ id: ToolID) {
        do {
            try FileManager.default.removeItem(at: ToolCatalog.managedDir(id))
        } catch {
            toolErrors[id] = error.localizedDescription
        }
        Task {
            await reloadPath()
            await refreshTools()
        }
    }
}
