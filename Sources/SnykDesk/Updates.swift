import AppKit
import Foundation
import SnykDeskCore

extension AppModel {
    static var currentVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.0.0-dev"
    }

    /// Asks GitHub for the latest release. Quiet unless `report` is set.
    func checkForUpdate(report: Bool = false) async {
        updateStatus = report ? "Checking…" : updateStatus
        guard let url = URL(string: Updater.latestReleaseAPI) else { return }
        var request = URLRequest(url: url)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.timeoutInterval = 15
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            guard status == 200 else {
                if report { updateStatus = "GitHub answered with status \(status)." }
                return
            }
            if let info = Updater.parse(data, current: Self.currentVersion) {
                availableUpdate = info
                updateStatus = "Version \(info.version) is available."
            } else {
                availableUpdate = nil
                if report { updateStatus = "You have the latest version (\(Self.currentVersion))." }
            }
        } catch {
            if report { updateStatus = "Could not check: \(error.localizedDescription)" }
            AppLog.write("update check failed: \(error.localizedDescription)")
        }
    }

    /// Downloads the new app, then lets a small script replace this one after it quits.
    func installUpdate() {
        guard let info = availableUpdate, !isUpdating else { return }
        let destination = Bundle.main.bundleURL
        guard destination.pathExtension == "app" else {
            updateStatus = "Run Snyk Desk from the Applications folder to update it from the app."
            return
        }
        isUpdating = true
        updateFraction = 0
        updateStatus = "Downloading \(info.version)…"
        AppLog.write("update: downloading \(info.version)")
        Task {
            do {
                let archive = try await FileDownloader.download(urls: [info.assetURL]) { [weak self] value in
                    Task { @MainActor in self?.updateFraction = value }
                }
                defer { try? FileManager.default.removeItem(at: archive) }
                updateStatus = "Unpacking…"
                let staging = FileManager.default.temporaryDirectory
                    .appendingPathComponent("snykdesk-update-\(UUID().uuidString)", isDirectory: true)
                try FileManager.default.createDirectory(at: staging, withIntermediateDirectories: true)
                let result = await Task.detached {
                    Shell.run("/usr/bin/ditto", ["-x", "-k", archive.path, staging.path])
                }.value
                guard result.status == 0 else { throw DeskError("Could not unpack the update: \(result.output)") }
                let newApp = staging.appendingPathComponent("Snyk Desk.app")
                guard FileManager.default.fileExists(atPath: newApp.path) else {
                    throw DeskError("The download does not contain Snyk Desk.app.")
                }
                let script = staging.appendingPathComponent("swap.sh")
                try Updater.swapScript(pid: ProcessInfo.processInfo.processIdentifier,
                                       newApp: newApp.path, destination: destination.path)
                    .write(to: script, atomically: true, encoding: .utf8)
                let process = Process()
                process.executableURL = URL(fileURLWithPath: "/bin/bash")
                process.arguments = [script.path]
                try process.run()
                AppLog.write("update: restarting into \(info.version)")
                updateStatus = "Restarting…"
                NSApplication.shared.terminate(nil)
            } catch {
                isUpdating = false
                updateStatus = error.localizedDescription
                AppLog.write("update failed: \(error.localizedDescription)")
            }
        }
    }
}
