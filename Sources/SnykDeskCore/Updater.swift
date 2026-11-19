import Foundation

/// A newer release on GitHub.
public struct UpdateInfo: Equatable, Sendable {
    public var version: String
    public var assetURL: String
    public var notes: String
}

public enum Updater {
    public static let latestReleaseAPI = "https://api.github.com/repos/bodco/snyk-desk/releases/latest"

    /// Numeric parts of "v0.2.10" -> [0, 2, 10]. Anything after a dash (0.3.0-dev) is ignored.
    public static func parts(_ version: String) -> [Int] {
        var text = version.trimmingCharacters(in: .whitespaces)
        if text.hasPrefix("v") || text.hasPrefix("V") { text.removeFirst() }
        let core = text.split(separator: "-").first.map(String.init) ?? text
        return core.split(separator: ".").map { Int($0) ?? 0 }
    }

    public static func isNewer(_ candidate: String, than current: String) -> Bool {
        let a = parts(candidate), b = parts(current)
        for index in 0..<max(a.count, b.count) {
            let x = index < a.count ? a[index] : 0
            let y = index < b.count ? b[index] : 0
            if x != y { return x > y }
        }
        return false
    }

    /// Reads the GitHub "latest release" answer. Returns nil when it is not newer or has no app zip.
    public static func parse(_ data: Data, current: String) -> UpdateInfo? {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let tag = object["tag_name"] as? String, isNewer(tag, than: current) else { return nil }
        let assets = (object["assets"] as? [[String: Any]]) ?? []
        guard let zip = assets.first(where: { ($0["name"] as? String)?.hasSuffix(".zip") == true }),
              let url = zip["browser_download_url"] as? String, url.hasPrefix("https://") else { return nil }
        let version = tag.hasPrefix("v") ? String(tag.dropFirst()) : tag
        return UpdateInfo(version: version, assetURL: url, notes: (object["body"] as? String) ?? "")
    }

    /// The script that swaps the app after it quits and starts it again.
    /// Files written by the app itself carry no quarantine mark, so Gatekeeper does not ask again.
    public static func swapScript(pid: Int32, newApp: String, destination: String) -> String {
        let new = LauncherGenerator.shellQuote(newApp)
        let dest = LauncherGenerator.shellQuote(destination)
        return """
        #!/bin/bash
        while kill -0 \(pid) 2>/dev/null; do sleep 0.3; done
        rm -rf \(dest)
        /usr/bin/ditto \(new) \(dest) || exit 1
        /usr/bin/xattr -dr com.apple.quarantine \(dest) 2>/dev/null
        /usr/bin/open \(dest)
        """
    }
}
