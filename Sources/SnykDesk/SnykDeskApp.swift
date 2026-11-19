import AppKit
import SwiftUI
import SnykDeskCore

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }
}

@main
struct SnykDeskApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = AppModel()

    var body: some Scene {
        Window("Snyk Desk", id: "main") {
            RootView()
                .environmentObject(model)
                .frame(minWidth: 920, minHeight: 620)
        }
        .windowResizability(.contentMinSize)

        MenuBarExtra("Snyk Desk", systemImage: "shield.lefthalf.filled") {
            MenuBarContent()
                .environmentObject(model)
        }
    }
}

struct RootView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Group {
            if model.config.onboardingDone {
                MainView()
            } else {
                OnboardingView()
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            model.reloadRuns()
        }
        .alert("Snyk Desk", isPresented: Binding(
            get: { model.lastError != nil },
            set: { if !$0 { model.lastError = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.lastError ?? "")
        }
    }
}

struct MenuBarContent: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        if let scan = model.activeScan {
            Text("Scanning: \(scan.step)")
        } else {
            let totals = model.totalCounts
            Text("Critical \(totals.critical), High \(totals.high), Medium \(totals.medium), Low \(totals.low)")
        }
        Divider()
        Button("Scan all now") {
            model.scan(model.config.repos.map(\.id))
        }
        .disabled(model.activeScan != nil || model.config.repos.isEmpty)
        Button("Open Snyk Desk") {
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }
        Divider()
        Button("Quit Snyk Desk") { NSApp.terminate(nil) }
    }
}

enum SidebarItem: String, CaseIterable, Identifiable, Hashable {
    case dashboard, projects, schedule, settings

    var id: String { rawValue }

    var title: String {
        switch self {
        case .dashboard: return "Dashboard"
        case .projects: return "Projects"
        case .schedule: return "Schedule"
        case .settings: return "Settings"
        }
    }

    var icon: String {
        switch self {
        case .dashboard: return "square.grid.2x2"
        case .projects: return "folder"
        case .schedule: return "calendar.badge.clock"
        case .settings: return "gearshape"
        }
    }
}

struct MainView: View {
    @State private var selection: SidebarItem? = .dashboard
    @State private var selectedRepo: UUID?

    var body: some View {
        NavigationSplitView {
            List(SidebarItem.allCases, selection: $selection) { item in
                Label(item.title, systemImage: item.icon).tag(item)
            }
            .navigationSplitViewColumnWidth(min: 170, ideal: 190)
        } detail: {
            switch selection ?? .dashboard {
            case .dashboard:
                DashboardView { id in
                    selectedRepo = id
                    selection = .projects
                }
            case .projects:
                ProjectsView(selected: $selectedRepo)
            case .schedule:
                ScheduleView()
            case .settings:
                SettingsView()
            }
        }
    }
}
