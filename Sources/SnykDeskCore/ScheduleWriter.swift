import Foundation

/// Writes and loads the launchd agent that runs the launcher on a schedule,
/// so scans happen even when the app is closed.
public enum ScheduleWriter {
    /// launchd counts Sunday as 0, Calendar counts it as 1.
    public static func launchdWeekday(_ calendarWeekday: Int) -> Int {
        ((calendarWeekday - 1) % 7 + 7) % 7
    }

    public static func plist(launcher: String, schedule: ScheduleConfig, logDir: String) -> [String: Any] {
        var interval: [String: Int] = ["Hour": schedule.hour, "Minute": schedule.minute]
        if schedule.frequency == .weekly {
            interval["Weekday"] = launchdWeekday(schedule.weekday)
        }
        return [
            "Label": Paths.agentLabel,
            "ProgramArguments": ["/bin/bash", launcher, "--scheduled"],
            "StartCalendarInterval": interval,
            "StandardOutPath": logDir + "/scheduled.log",
            "StandardErrorPath": logDir + "/scheduled.log",
            "RunAtLoad": false
        ]
    }

    public static func plistData(launcher: String, schedule: ScheduleConfig, logDir: String) throws -> Data {
        try PropertyListSerialization.data(
            fromPropertyList: plist(launcher: launcher, schedule: schedule, logDir: logDir),
            format: .xml, options: 0)
    }

    public static func nextRun(_ schedule: ScheduleConfig, after date: Date = Date(), calendar: Calendar = .current) -> Date? {
        var components = DateComponents()
        components.hour = schedule.hour
        components.minute = schedule.minute
        if schedule.frequency == .weekly { components.weekday = schedule.weekday }
        return calendar.nextDate(after: date, matching: components, matchingPolicy: .nextTime)
    }

    public static var isInstalled: Bool {
        FileManager.default.fileExists(atPath: Paths.agentPlist.path)
    }

    static var domain: String { "gui/\(getuid())" }

    public static func install(launcher: String, schedule: ScheduleConfig) throws {
        Paths.ensure(Paths.logs)
        Paths.ensure(Paths.agentPlist.deletingLastPathComponent())
        let data = try plistData(launcher: launcher, schedule: schedule, logDir: Paths.logs.path)
        Shell.run("/bin/launchctl", ["bootout", domain, Paths.agentPlist.path])
        try data.write(to: Paths.agentPlist, options: .atomic)
        let result = Shell.run("/bin/launchctl", ["bootstrap", domain, Paths.agentPlist.path])
        if result.status != 0 {
            throw DeskError("launchctl could not load the schedule: \(result.output.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
    }

    public static func uninstall() {
        Shell.run("/bin/launchctl", ["bootout", domain, Paths.agentPlist.path])
        try? FileManager.default.removeItem(at: Paths.agentPlist)
    }
}
