import Foundation

public enum Shell {
    /// Runs a program to completion and returns its exit status and combined output.
    @discardableResult
    public static func run(_ executable: String, _ arguments: [String],
                           environment: [String: String]? = nil,
                           directory: String? = nil) -> (status: Int32, output: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        if let environment { process.environment = environment }
        if let directory { process.currentDirectoryURL = URL(fileURLWithPath: directory) }
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return (-1, error.localizedDescription)
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(decoding: data, as: UTF8.self))
    }

    /// Folders where developer tools usually live, so launchd and the app find snyk, node, mvn.
    public static var commonDirs: [String] {
        let home = Paths.home.path
        return [
            Paths.bin.path,
            "\(home)/.npm-global/bin",
            "\(home)/.homebrew/bin",
            "\(home)/.local/bin",
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/usr/bin", "/bin", "/usr/sbin", "/sbin"
        ]
    }

    /// PATH from the user's login shell, merged with common tool folders.
    public static func userPATH() -> String {
        let marker = "__SNYKDESK_PATH__"
        let result = run("/bin/zsh", ["-l", "-c", "printf '\(marker)%s' \"$PATH\""])
        var dirs: [String] = []
        if result.status == 0, let range = result.output.range(of: marker) {
            let value = result.output[range.upperBound...].trimmingCharacters(in: .whitespacesAndNewlines)
            dirs = value.split(separator: ":").map(String.init)
        }
        return merge(dirs, commonDirs)
    }

    public static func merge(_ first: [String], _ second: [String]) -> String {
        var out: [String] = []
        for dir in first + second where !dir.isEmpty && !out.contains(dir) {
            out.append(dir)
        }
        return out.joined(separator: ":")
    }

    public static func find(_ command: String, in path: String) -> String? {
        for dir in path.split(separator: ":") {
            let candidate = "\(dir)/\(command)"
            if FileManager.default.isExecutableFile(atPath: candidate) { return candidate }
        }
        return nil
    }

    /// The current process environment with PATH replaced.
    public static func environment(path: String) -> [String: String] {
        var env = ProcessInfo.processInfo.environment
        env["PATH"] = path
        if env["HOME"] == nil { env["HOME"] = Paths.home.path }
        return env
    }
}
