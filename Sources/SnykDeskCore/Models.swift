import Foundation

public enum Severity: String, Codable, CaseIterable, Comparable, Sendable {
    case critical, high, medium, low

    public var rank: Int {
        switch self {
        case .critical: return 0
        case .high: return 1
        case .medium: return 2
        case .low: return 3
        }
    }

    public static func < (lhs: Severity, rhs: Severity) -> Bool { lhs.rank < rhs.rank }

    public var label: String { rawValue.capitalized }
    public var letter: String { String(rawValue.prefix(1)).uppercased() }

    public init(snyk value: String) {
        self = Severity(rawValue: value.lowercased()) ?? .low
    }
}

public struct SeverityCounts: Codable, Equatable, Sendable {
    public var critical: Int
    public var high: Int
    public var medium: Int
    public var low: Int

    public init(critical: Int = 0, high: Int = 0, medium: Int = 0, low: Int = 0) {
        self.critical = critical
        self.high = high
        self.medium = medium
        self.low = low
    }

    public subscript(severity: Severity) -> Int {
        get {
            switch severity {
            case .critical: return critical
            case .high: return high
            case .medium: return medium
            case .low: return low
            }
        }
        set {
            switch severity {
            case .critical: critical = newValue
            case .high: high = newValue
            case .medium: medium = newValue
            case .low: low = newValue
            }
        }
    }

    public var total: Int { critical + high + medium + low }

    public static func + (lhs: SeverityCounts, rhs: SeverityCounts) -> SeverityCounts {
        SeverityCounts(critical: lhs.critical + rhs.critical,
                       high: lhs.high + rhs.high,
                       medium: lhs.medium + rhs.medium,
                       low: lhs.low + rhs.low)
    }

    public static func of(_ findings: [Finding]) -> SeverityCounts {
        var counts = SeverityCounts()
        for finding in findings { counts[finding.severity] += 1 }
        return counts
    }
}

public enum FindingKind: String, Codable, Sendable {
    case dependency, code
}

public struct Finding: Codable, Identifiable, Hashable, Sendable {
    public var id: String
    public var kind: FindingKind
    public var severity: Severity
    public var title: String
    public var issueId: String
    public var location: String
    public var detail: String
    public var fix: String?
    public var url: String?
    /// CWE ids such as "CWE-79".
    public var cwe: [String]?
    /// Snyk's own explanation of the problem, shortened.
    public var advice: String?
    public var cve: [String]?
    /// CVSS score from Snyk, when it gives one.
    public var score: Double?

    public init(id: String, kind: FindingKind, severity: Severity, title: String, issueId: String,
                location: String, detail: String, fix: String? = nil, url: String? = nil,
                cwe: [String]? = nil, advice: String? = nil, cve: [String]? = nil, score: Double? = nil) {
        self.id = id
        self.kind = kind
        self.severity = severity
        self.title = title
        self.issueId = issueId
        self.location = location
        self.detail = detail
        self.fix = fix
        self.url = url
        self.cwe = cwe
        self.advice = advice
        self.cve = cve
        self.score = score
    }
}

/// Outcome of one scan step, derived from the Snyk CLI exit code.
public enum StepStatus: String, Codable, Sendable {
    case clean, issues, error, unsupported, skipped

    /// Snyk CLI exit codes: 0 no issues, 1 issues found, 2 error, 3 no supported projects.
    public static func fromExit(_ code: Int?) -> StepStatus {
        guard let code else { return .skipped }
        switch code {
        case 0: return .clean
        case 1: return .issues
        case 3: return .unsupported
        default: return .error
        }
    }

    public var label: String {
        switch self {
        case .clean: return "No issues"
        case .issues: return "Issues found"
        case .error: return "Error"
        case .unsupported: return "Nothing to scan"
        case .skipped: return "Off"
        }
    }

    /// Whether the step ran against Snyk and likely used a test from the monthly quota.
    public var consumedTest: Bool {
        self == .clean || self == .issues || self == .error
    }
}

public struct ScanRun: Identifiable, Equatable, Sendable {
    public var id: String
    public var repoId: UUID
    public var date: Date
    public var dependencies: StepStatus
    public var code: StepStatus
    public var monitor: StepStatus
    public var dependencyProjects: Int
    public var findings: [Finding]
    public var notes: [String]
    /// The scan folder, so the UI can open the logs. Nil for runs built in memory.
    public var directory: URL?

    public init(id: String, repoId: UUID, date: Date, dependencies: StepStatus, code: StepStatus,
                monitor: StepStatus, dependencyProjects: Int, findings: [Finding], notes: [String],
                directory: URL? = nil) {
        self.id = id
        self.repoId = repoId
        self.date = date
        self.dependencies = dependencies
        self.code = code
        self.monitor = monitor
        self.dependencyProjects = dependencyProjects
        self.findings = findings
        self.notes = notes
        self.directory = directory
    }

    public var counts: SeverityCounts { SeverityCounts.of(findings) }
}

public struct RepoConfig: Codable, Identifiable, Hashable, Sendable {
    public var id: UUID
    public var name: String
    public var path: String
    /// Project the repository belongs to; one project can hold several repositories.
    public var project: String
    public var scanDependencies: Bool
    public var scanCode: Bool
    public var monitor: Bool
    public var scheduled: Bool
    /// Where this repository's scans go. nil means the default: a subfolder next to the launcher.
    public var resultsFolder: String?

    public init(id: UUID = UUID(), name: String, path: String, project: String? = nil,
                scanDependencies: Bool = true, scanCode: Bool = true, monitor: Bool = true,
                scheduled: Bool = true, resultsFolder: String? = nil) {
        self.id = id
        self.name = name
        self.path = path
        self.project = project ?? ProjectInference.guess(path: path)
        self.scanDependencies = scanDependencies
        self.scanCode = scanCode
        self.monitor = monitor
        self.scheduled = scheduled
        self.resultsFolder = resultsFolder
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        name = try c.decodeIfPresent(String.self, forKey: .name) ?? "Repository"
        path = try c.decodeIfPresent(String.self, forKey: .path) ?? ""
        project = try c.decodeIfPresent(String.self, forKey: .project) ?? ProjectInference.guess(path: path)
        scanDependencies = try c.decodeIfPresent(Bool.self, forKey: .scanDependencies) ?? true
        scanCode = try c.decodeIfPresent(Bool.self, forKey: .scanCode) ?? true
        monitor = try c.decodeIfPresent(Bool.self, forKey: .monitor) ?? true
        scheduled = try c.decodeIfPresent(Bool.self, forKey: .scheduled) ?? true
        resultsFolder = try c.decodeIfPresent(String.self, forKey: .resultsFolder)
    }
}

/// Guesses a project name from a repository path:
/// `.../bink/repos/api` gives "bink", `.../Pacenote/app` gives "Pacenote".
public enum ProjectInference {
    static let containerNames: Set<String> = ["repos", "repositories", "src", "code", "git", "projects"]

    public static func guess(path: String) -> String {
        let parent = URL(fileURLWithPath: path).deletingLastPathComponent()
        let parentName = parent.lastPathComponent
        if containerNames.contains(parentName.lowercased()) {
            let grandparent = parent.deletingLastPathComponent().lastPathComponent
            if !grandparent.isEmpty && grandparent != "/" { return grandparent }
        }
        if parentName.isEmpty || parentName == "/" { return "Other" }
        return parentName
    }
}

/// Decides where each repository's scan results are written.
public enum ResultsLocation {
    static func sanitize(_ value: String) -> String {
        var cleaned = value
        for character in ["/", ":", "|"] {
            cleaned = cleaned.replacingOccurrences(of: character, with: "-")
        }
        cleaned = cleaned.trimmingCharacters(in: .whitespaces)
        if cleaned.isEmpty || cleaned.hasPrefix(".") { cleaned = "repo" + cleaned }
        return cleaned
    }

    /// Default repository subfolder: the repository folder's own name, which does not change when the repo is renamed in the app.
    /// Two repositories of one project with the same folder name get a short id suffix so their scans never mix.
    public static func defaultFolderName(for repo: RepoConfig, in repos: [RepoConfig]) -> String {
        let base = sanitize(URL(fileURLWithPath: repo.path).lastPathComponent)
        let project = sanitize(repo.project)
        let clash = repos.contains { other in
            other.id != repo.id && sanitize(other.project) == project
                && sanitize(URL(fileURLWithPath: other.path).lastPathComponent) == base
        }
        return clash ? "\(base)-\(repo.id.uuidString.prefix(4).lowercased())" : base
    }

    /// `<launcher folder>/<project>/<repository folder>`.
    public static func defaultFolder(for repo: RepoConfig, config: AppConfig) -> String {
        if let launcher = config.launcherFolder {
            return URL(fileURLWithPath: launcher)
                .appendingPathComponent(sanitize(repo.project), isDirectory: true)
                .appendingPathComponent(defaultFolderName(for: repo, in: config.repos), isDirectory: true).path
        }
        return Paths.results.appendingPathComponent(repo.id.uuidString, isDirectory: true).path
    }

    public static func folder(for repo: RepoConfig, config: AppConfig) -> String {
        if let custom = repo.resultsFolder, !custom.isEmpty { return custom }
        return defaultFolder(for: repo, config: config)
    }
}

public enum Frequency: String, Codable, CaseIterable, Sendable {
    case daily, weekly
}

public struct ScheduleConfig: Codable, Equatable, Sendable {
    public var enabled: Bool
    public var frequency: Frequency
    /// Calendar weekday: 1 = Sunday ... 7 = Saturday.
    public var weekday: Int
    public var hour: Int
    public var minute: Int

    public init(enabled: Bool = false, frequency: Frequency = .weekly, weekday: Int = 2, hour: Int = 10, minute: Int = 0) {
        self.enabled = enabled
        self.frequency = frequency
        self.weekday = weekday
        self.hour = hour
        self.minute = minute
    }
}

public struct AppConfig: Codable, Equatable, Sendable {
    public var onboardingDone: Bool = false
    public var launcherFolder: String? = nil
    public var snykPath: String? = nil
    public var repos: [RepoConfig] = []
    public var schedule: ScheduleConfig = ScheduleConfig()

    public init() {}

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        onboardingDone = try c.decodeIfPresent(Bool.self, forKey: .onboardingDone) ?? false
        launcherFolder = try c.decodeIfPresent(String.self, forKey: .launcherFolder)
        snykPath = try c.decodeIfPresent(String.self, forKey: .snykPath)
        repos = try c.decodeIfPresent([RepoConfig].self, forKey: .repos) ?? []
        schedule = try c.decodeIfPresent(ScheduleConfig.self, forKey: .schedule) ?? ScheduleConfig()
    }
}

public struct DeskError: LocalizedError {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var errorDescription: String? { message }
}
