import Foundation

public enum Paths {
    /// Tests point this at a temporary folder.
    public static var rootOverride: URL? = nil

    public static var home: URL { FileManager.default.homeDirectoryForCurrentUser }

    public static var support: URL {
        rootOverride ?? home.appendingPathComponent("Library/Application Support/SnykDesk", isDirectory: true)
    }

    public static var configFile: URL { support.appendingPathComponent("config.json") }
    public static var results: URL { support.appendingPathComponent("results", isDirectory: true) }
    public static var bin: URL { support.appendingPathComponent("bin", isDirectory: true) }
    public static var logs: URL { support.appendingPathComponent("logs", isDirectory: true) }

    public static let launcherName = "snyk-desk-scan.sh"
    public static let launcherMarker = "SNYK-DESK-LAUNCHER"
    public static let agentLabel = "pm.bodco.snykdesk.scan"

    public static var agentPlist: URL {
        home.appendingPathComponent("Library/LaunchAgents/\(agentLabel).plist")
    }

    public static func ensure(_ url: URL) {
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    }
}

public enum ConfigStore {
    public static func load() -> AppConfig {
        guard let data = try? Data(contentsOf: Paths.configFile),
              let config = try? JSONDecoder().decode(AppConfig.self, from: data) else {
            return AppConfig()
        }
        return config
    }

    public static func save(_ config: AppConfig) throws {
        Paths.ensure(Paths.support)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(config).write(to: Paths.configFile, options: .atomic)
    }
}
