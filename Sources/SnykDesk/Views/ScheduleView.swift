import SwiftUI
import SnykDeskCore

struct ScheduleView: View {
    @EnvironmentObject private var model: AppModel

    private var schedule: ScheduleConfig { model.config.schedule }

    private var time: Binding<Date> {
        Binding(
            get: {
                Calendar.current.date(bySettingHour: schedule.hour, minute: schedule.minute, second: 0, of: Date()) ?? Date()
            },
            set: { date in
                let parts = Calendar.current.dateComponents([.hour, .minute], from: date)
                model.config.schedule.hour = parts.hour ?? 10
                model.config.schedule.minute = parts.minute ?? 0
            })
    }

    private var scheduledCount: Int { model.config.repos.filter(\.scheduled).count }

    var body: some View {
        Form {
            Section("When") {
                Toggle("Scan automatically", isOn: $model.config.schedule.enabled)
                Picker("Frequency", selection: $model.config.schedule.frequency) {
                    Text("Every day").tag(Frequency.daily)
                    Text("Every week").tag(Frequency.weekly)
                }
                if schedule.frequency == .weekly {
                    Picker("Day", selection: $model.config.schedule.weekday) {
                        ForEach(1...7, id: \.self) { day in
                            Text(Calendar.current.weekdaySymbols[day - 1]).tag(day)
                        }
                    }
                }
                DatePicker("Time", selection: time, displayedComponents: .hourAndMinute)
            }

            Section("Repositories in the schedule") {
                if model.config.repos.isEmpty {
                    Text("No repositories yet. Add them in Settings.").foregroundStyle(.secondary)
                }
                ForEach($model.config.repos) { $repo in
                    Toggle(isOn: $repo.scheduled) {
                        VStack(alignment: .leading) {
                            Text(repo.name)
                            Text(enabledSteps(repo)).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }

            Section {
                HStack {
                    Button("Apply") { model.applySchedule() }
                        .buttonStyle(.borderedProminent)
                    Text(model.scheduleInstalled ? "Installed in launchd" : "Not installed")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if let message = model.scheduleMessage {
                    Text(message).font(.callout)
                }
                if schedule.enabled, let next = ScheduleWriter.nextRun(schedule) {
                    Text("Next scan: \(next.formatted(date: .complete, time: .shortened)), \(scheduledCount) repositories.")
                        .font(.callout)
                }
                Text("The schedule runs through launchd, so it works while the app is closed. If the Mac is asleep at that time, the scan runs after it wakes up. Each scan uses Free plan tests, so weekly is usually enough.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .padding(.top, 8)
    }

    private func enabledSteps(_ repo: RepoConfig) -> String {
        var steps: [String] = []
        if repo.scanDependencies { steps.append("dependencies") }
        if repo.scanCode { steps.append("code") }
        if repo.monitor { steps.append("monitor") }
        return steps.isEmpty ? "Nothing to scan" : steps.joined(separator: ", ")
    }
}
