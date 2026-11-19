import Foundation

/// A small append-only log for the app itself: launcher writes, scan starts and ends, tool installs.
/// It lives in Application Support/SnykDesk/logs/snyk-desk.log and is rotated at 1 MB.
public enum AppLog {
    public static let maxBytes = 1_000_000
    private static let lock = NSLock()

    public static var file: URL { Paths.logs.appendingPathComponent("snyk-desk.log") }

    static let stamp: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter
    }()

    public static func write(_ message: String) {
        lock.lock()
        defer { lock.unlock() }
        Paths.ensure(Paths.logs)
        rotateIfNeeded()
        let line = "\(stamp.string(from: Date())) \(message)\n"
        guard let data = line.data(using: .utf8) else { return }
        if let handle = try? FileHandle(forWritingTo: file) {
            defer { try? handle.close() }
            _ = try? handle.seekToEnd()
            try? handle.write(contentsOf: data)
        } else {
            try? data.write(to: file)
        }
    }

    static func rotateIfNeeded() {
        let size = (try? FileManager.default.attributesOfItem(atPath: file.path))?[.size] as? Int ?? 0
        guard size > maxBytes else { return }
        let old = Paths.logs.appendingPathComponent("snyk-desk.old.log")
        try? FileManager.default.removeItem(at: old)
        try? FileManager.default.moveItem(at: file, to: old)
    }
}
