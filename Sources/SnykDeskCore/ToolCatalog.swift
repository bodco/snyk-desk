import Foundation

/// Build tools the Snyk CLI shells out to. Without them a dependency scan of a Maven, Gradle,
/// Node or Go project fails with a generic "SNYK-CLI-0000" error.
public enum ToolID: String, CaseIterable, Codable, Sendable, Identifiable {
    case commandLineTools, java, maven, gradle, node, go

    public var id: String { rawValue }
}

public enum ArchiveKind: Equatable, Sendable {
    case tarGz, zip
}

public enum ToolInstallKind: Equatable, Sendable {
    /// Installed by the macOS "Install Command Line Developer Tools" dialog.
    case system
    /// Downloaded from the vendor and unpacked into the app's own folder. No admin rights needed.
    case download(archive: ArchiveKind, urls: [String])
}

public struct ToolSpec: Equatable, Sendable, Identifiable {
    public let id: ToolID
    public let title: String
    public let purpose: String
    /// Executable to look for on PATH.
    public let command: String
    /// Arguments that print the version (empty to skip it).
    public let versionArgs: [String]
    /// Folder with the executable, relative to the managed install folder.
    public let binSubpath: String
    public let install: ToolInstallKind
    public let approxSizeMB: Int
}

public enum ToolCatalog {
    public static var arch: (jdk: String, node: String, go: String) {
        #if arch(arm64)
        return ("aarch64", "arm64", "arm64")
        #else
        return ("x64", "x64", "amd64")
        #endif
    }

    public static var all: [ToolSpec] {
        let a = arch
        return [
            ToolSpec(
                id: .java, title: "Java (JDK 21)",
                purpose: "Runs Maven and Gradle. Needed for Java and Kotlin projects.",
                command: "java", versionArgs: ["-version"], binSubpath: "Contents/Home/bin",
                install: .download(archive: .tarGz, urls: [
                    "https://api.adoptium.net/v3/binary/latest/21/ga/mac/\(a.jdk)/jdk/hotspot/normal/eclipse"
                ]),
                approxSizeMB: 190),
            ToolSpec(
                id: .maven, title: "Maven",
                purpose: "Resolves the dependencies of projects with a pom.xml.",
                command: "mvn", versionArgs: [], binSubpath: "bin",
                install: .download(archive: .tarGz, urls: [
                    "https://archive.apache.org/dist/maven/maven-3/3.9.9/binaries/apache-maven-3.9.9-bin.tar.gz",
                    "https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.9/apache-maven-3.9.9-bin.tar.gz"
                ]),
                approxSizeMB: 9),
            ToolSpec(
                id: .gradle, title: "Gradle",
                purpose: "Resolves the dependencies of Gradle projects that have no gradlew wrapper.",
                command: "gradle", versionArgs: [], binSubpath: "bin",
                install: .download(archive: .zip, urls: [
                    "https://services.gradle.org/distributions/gradle-8.10.2-bin.zip"
                ]),
                approxSizeMB: 130),
            ToolSpec(
                id: .node, title: "Node.js",
                purpose: "Needed for npm projects that have no lock file.",
                command: "node", versionArgs: ["--version"], binSubpath: "bin",
                install: .download(archive: .tarGz, urls: [
                    "https://nodejs.org/dist/v22.11.0/node-v22.11.0-darwin-\(a.node).tar.gz"
                ]),
                approxSizeMB: 45),
            ToolSpec(
                id: .go, title: "Go",
                purpose: "Needed for Go modules (go.mod).",
                command: "go", versionArgs: ["version"], binSubpath: "bin",
                install: .download(archive: .tarGz, urls: [
                    "https://go.dev/dl/go1.23.3.darwin-\(a.go).tar.gz"
                ]),
                approxSizeMB: 70),
            ToolSpec(
                id: .commandLineTools, title: "Xcode Command Line Tools",
                purpose: "Gives you git, Python 3 and Swift. Needed for Python and Swift projects.",
                command: "git", versionArgs: [], binSubpath: "",
                install: .system, approxSizeMB: 700)
        ]
    }

    public static func spec(_ id: ToolID) -> ToolSpec {
        all.first { $0.id == id }!
    }

    // MARK: Managed installs

    public static func managedDir(_ id: ToolID) -> URL {
        Paths.tools.appendingPathComponent(id.rawValue, isDirectory: true)
    }

    public static func managedBin(_ id: ToolID) -> URL {
        let spec = spec(id)
        if spec.binSubpath.isEmpty { return managedDir(id) }
        return managedDir(id).appendingPathComponent(spec.binSubpath, isDirectory: true)
    }

    public static func isManagedInstalled(_ id: ToolID) -> Bool {
        let spec = spec(id)
        guard spec.install != .system else { return false }
        return FileManager.default.isExecutableFile(atPath: managedBin(id).appendingPathComponent(spec.command).path)
    }

    /// Bin folders of the tools the app installed, for PATH.
    public static func managedBinDirs() -> [String] {
        all.filter { isManagedInstalled($0.id) }.map { managedBin($0.id).path }
    }

    /// JAVA_HOME of the app's own JDK, if it installed one.
    public static func managedJavaHome() -> String? {
        guard isManagedInstalled(.java) else { return nil }
        return managedDir(.java).appendingPathComponent("Contents/Home", isDirectory: true).path
    }
}

public enum ToolStatus: Equatable, Sendable {
    case missing
    case found(path: String, version: String, managed: Bool)

    public var isFound: Bool {
        if case .found = self { return true }
        return false
    }
}

public enum ToolDetector {
    /// Looks for the tool on `path`, then in the app's own tools folder.
    /// Java is run, not just looked up, because macOS ships a /usr/bin/java stub that exists but fails.
    public static func detect(_ spec: ToolSpec, path: String) -> ToolStatus {
        if spec.id == .commandLineTools {
            let result = Shell.run("/usr/bin/xcode-select", ["-p"])
            let folder = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
            if result.status == 0, !folder.isEmpty {
                return .found(path: folder, version: "", managed: false)
            }
            return .missing
        }

        var candidates: [String] = []
        if let onPath = Shell.find(spec.command, in: path) { candidates.append(onPath) }
        let own = managedBin(spec.id).appendingPathComponent(spec.command).path
        if FileManager.default.isExecutableFile(atPath: own), !candidates.contains(own) { candidates.append(own) }

        for candidate in candidates {
            let managed = candidate.hasPrefix(Paths.tools.path)
            var version = ""
            if spec.id == .java || !spec.versionArgs.isEmpty {
                var env = Shell.environment(path: path)
                if managed, spec.id == .java { env["JAVA_HOME"] = ToolCatalog.managedJavaHome() }
                let result = Shell.run(candidate, spec.versionArgs, environment: env)
                if spec.id == .java && result.status != 0 { continue }
                version = result.output.split(separator: "\n").first.map(String.init)?
                    .trimmingCharacters(in: .whitespaces) ?? ""
            }
            return .found(path: candidate, version: version, managed: managed)
        }
        return .missing
    }

    private static func managedBin(_ id: ToolID) -> URL { ToolCatalog.managedBin(id) }
}

/// Works out which tools the configured repositories need, by looking for build files.
public enum RepoRequirements {
    private static let skipFolders: Set<String> = ["node_modules", "target", "build", "Pods", "venv", "dist", "__pycache__"]
    private static let lockFiles = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]
    private static let pythonSwiftFiles: Set<String> = ["Package.swift", "requirements.txt", "pyproject.toml", "Pipfile", "setup.py"]

    /// Tools needed to scan one repository folder. Looks a few levels deep and skips build output.
    public static func needs(path: String) -> Set<ToolID> {
        let base = URL(fileURLWithPath: path).resolvingSymlinksInPath()
        let fm = FileManager.default
        guard let walker = fm.enumerator(at: base, includingPropertiesForKeys: [.isDirectoryKey],
                                         options: [.skipsHiddenFiles]) else { return [] }
        var found = Set<ToolID>()
        var seen = 0
        let baseDepth = base.pathComponents.count
        while let item = walker.nextObject() as? URL {
            seen += 1
            if seen > 6000 { break }
            let name = item.lastPathComponent
            let depth = item.pathComponents.count - baseDepth
            let isDirectory = (try? item.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) ?? false
            if isDirectory {
                if skipFolders.contains(name) || depth >= 4 { walker.skipDescendants() }
                continue
            }
            let dir = item.deletingLastPathComponent()
            switch name {
            case "pom.xml":
                found.insert(.maven)
                found.insert(.java)
            case "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts":
                found.insert(.java)
                let wrapper = fm.fileExists(atPath: dir.appendingPathComponent("gradlew").path)
                    || fm.fileExists(atPath: base.appendingPathComponent("gradlew").path)
                if !wrapper { found.insert(.gradle) }
            case "package.json":
                let locked = lockFiles.contains { fm.fileExists(atPath: dir.appendingPathComponent($0).path) }
                if !locked { found.insert(.node) }
            case "go.mod":
                found.insert(.go)
            default:
                if pythonSwiftFiles.contains(name) { found.insert(.commandLineTools) }
            }
        }
        return found
    }

    /// Tool to names of the repositories that need it. Only repositories whose dependencies
    /// are scanned count, because code scans need no build tools.
    public static func needs(for repos: [RepoConfig]) -> [ToolID: [String]] {
        var result: [ToolID: [String]] = [:]
        for repo in repos where repo.scanDependencies || repo.monitor {
            for tool in needs(path: repo.path) {
                result[tool, default: []].append(repo.name)
            }
        }
        return result
    }
}

/// Unpacks a downloaded tool into its own folder.
public enum ToolUnpacker {
    /// Extracts the archive and moves its single top-level folder to `destination`,
    /// replacing whatever was there.
    public static func unpack(archive: URL, kind: ArchiveKind, into destination: URL) throws {
        let fm = FileManager.default
        let parent = destination.deletingLastPathComponent()
        Paths.ensure(parent)
        let staging = parent.appendingPathComponent(".unpack-\(UUID().uuidString)", isDirectory: true)
        try fm.createDirectory(at: staging, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: staging) }

        let result: (status: Int32, output: String)
        switch kind {
        case .tarGz:
            result = Shell.run("/usr/bin/tar", ["-xzf", archive.path, "-C", staging.path])
        case .zip:
            result = Shell.run("/usr/bin/ditto", ["-x", "-k", archive.path, staging.path])
        }
        guard result.status == 0 else {
            throw DeskError("Could not unpack the download: \(result.output.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
        let items = try fm.contentsOfDirectory(atPath: staging.path)
            .filter { !$0.hasPrefix(".") && $0 != "__MACOSX" }
        guard items.count == 1 else {
            throw DeskError("The download has an unexpected layout (\(items.count) top-level items).")
        }
        if fm.fileExists(atPath: destination.path) { try fm.removeItem(at: destination) }
        try fm.moveItem(at: staging.appendingPathComponent(items[0]), to: destination)
    }
}
