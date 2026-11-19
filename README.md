# Snyk Desk

[Українська версія](README.uk.md)

A small native macOS app that runs the [Snyk CLI](https://docs.snyk.io/snyk-cli) against your local repositories, keeps the results, and shows them in one place. It works with any repository on disk, wherever it is hosted (GitHub, Bitbucket Server, GitLab or nowhere).

> Snyk Desk is an independent open source project. It is not affiliated with, endorsed by or sponsored by Snyk Ltd. "Snyk" is a trademark of Snyk Ltd.

## Features

- **Guided setup**: choose a folder for the scan launcher (an existing launcher is detected and kept), install the Snyk CLI with a progress bar or detect the one you have, pick repository folders, install the build tools they need, log in to Snyk.
- **Build tools without Terminal**: the app looks at your repositories (`pom.xml`, `build.gradle`, `package.json`, `go.mod`, Python and Swift files), shows which of Java, Maven, Gradle, Node.js, Go and the Xcode Command Line Tools they need, and installs the missing ones with one button and a progress bar. Downloads come from the official sites into the app's own folder, with no admin password and no Homebrew.
- **Projects with several repositories**: each repository belongs to a project, guessed from its path (`.../acme/repos/api` belongs to `acme`) and editable. The dashboard and the Projects tab are grouped by project, and a whole project can be scanned at once.
- **Dashboard**: severity totals across all repositories and per project, a card per repository with its latest scan, an empty state before the first scan.
- **Projects**: run one repository on its own, watch the progress and log, browse past scans, and filter findings by type (dependencies or code) and severity. Each finding shows the package or file, the dependency path and the fix version when there is one.
- **Per repository switches**: dependency scan (`snyk test`), code scan (`snyk code test`) and a snapshot to your Snyk dashboard (`snyk monitor`).
- **Results where you want them**: scans are saved next to the launcher by default, as `<project>/<repository>/<date-time>`. Any repository can use its own folder instead, for example inside that client's project folder.
- **Schedule**: daily or weekly scans of the repositories you pick, through launchd, so they run while the app is closed. A notification appears when a scheduled scan finishes.
- **Free plan friendly**: a local estimate of this month's Open Source and Code tests against the Free plan limits, and one aggregated Maven test per multi-module repository instead of one test per `pom.xml`.
- **Menu bar**: totals at a glance and a "Scan all now" button.

## Requirements

- macOS 14 Sonoma or newer, Apple Silicon.
- A Snyk account. The [Free plan](https://snyk.io/plans/) works.
- The build tools your projects need for dependency resolution (Maven for a `pom.xml`, Gradle, Node.js and so on). Snyk runs them to read the dependency tree. You do not have to install them yourself: setup and **Settings > Tools** list what is missing and install it. Tools you already have are used as they are.

## Install

1. Download `SnykDesk-<version>.zip` from [Releases](https://github.com/bodco/snyk-desk/releases).
2. Unzip it and move **Snyk Desk** to Applications.
3. The app is signed ad hoc and not notarized. The first time, right-click it and choose **Open**, or run:
   ```
   xattr -dr com.apple.quarantine "/Applications/Snyk Desk.app"
   ```

## How it works

```
Snyk Desk.app ──writes──> <launcher folder>/snyk-desk-scan.sh ──runs──> snyk test / code test / monitor
      │                            ▲                                            │
      │                            └── launchd agent (schedule)                 │
      └──reads── <results folder of the repo>/<timestamp>/ <──────────writes─────┘
```

- **Launcher.** The app generates one shell script, `snyk-desk-scan.sh`, in the folder you choose and rewrites it whenever the settings change. The app and the schedule both run it, so manual and scheduled scans behave the same way. You can also run it yourself:
  ```
  ./snyk-desk-scan.sh                 # repositories that are in the schedule
  ./snyk-desk-scan.sh <repo-id> ...   # specific repositories (ids are in config.json)
  ```
- **Results.** Each scan writes the raw Snyk output (`deps.json`, `code.json` in SARIF), the logs and the exit codes to `<results folder>/<timestamp>/`. By default the results folder of a repository is `<launcher folder>/<project>/<repository folder name>/`; two repositories of one project with the same folder name get a short suffix so their scans never mix. Changing a repository's project moves its default folder, so earlier scans stay in the old folder. In Settings or on the repository's page you can choose another folder, go back to the default, or open it in Finder. Nothing is written into your repositories unless you choose a folder inside one.
- **Settings** live in `~/Library/Application Support/SnykDesk/config.json`.
- **Schedule.** The app writes `~/Library/LaunchAgents/pm.bodco.snykdesk.scan.plist` and loads it with `launchctl`. If the Mac is asleep at the scheduled time, launchd runs the scan after it wakes up. Turning the schedule off removes the agent.
- **Login.** "Log in to Snyk" runs `snyk auth`, which opens your browser. The CLI stores the token in its own config. Snyk Desk never reads, shows or stores it.
- **Build tools.** Setup and Settings > Tools check each tool on your PATH and in `~/Library/Application Support/SnykDesk/tools`. Missing ones are downloaded from the official sites (Temurin JDK 21, Apache Maven, Gradle, Node.js, Go), unpacked there and added to the launcher's PATH and `JAVA_HOME`. Your own installs win over these. The Xcode Command Line Tools (git, Python 3, Swift) can only come from Apple's own installer, so the app opens it and waits. Before each dependency scan the launcher checks that the repository's build tool runs, and if it does not, the scan reports that in plain words instead of the generic `SNYK-CLI-0000` error.
- **Logs.** Each scan folder has `scan.log` (Snyk version, PATH, tool versions, commands, exit codes, durations) next to `deps.log`, `code.log` and `monitor.log`. After a failed Maven scan the launcher also saves Maven's own error to `maven.log`. The app's own log is `~/Library/Application Support/SnykDesk/logs/snyk-desk.log` (Settings > Logs > Open app log).
- **Copy for Claude.** "Copy to Claude" on a repository page copies a prompt with the path and the vulnerabilities currently shown (the severity and type filters apply). Each vulnerability has a copy menu: details only, details with a prompt, or a prompt for every finding of the same type. Paste into a Claude project that can read the code.
- **CLI install.** If `snyk` is not on your PATH, the app downloads the standalone binary from `downloads.snyk.io` into `~/Library/Application Support/SnykDesk/bin`. An existing install (npm, Homebrew) is used as is.

## Free plan limits

The Snyk Free plan has monthly test limits per product (at the time of writing: 200 Open Source, 100 Code, 100 Container, 300 IaC). Tests of public repositories do not count. When a limit runs out, tests stop until the next month. Check the current numbers on [snyk.io/plans](https://snyk.io/plans/).

How Snyk Desk uses tests, as far as it can tell:

| Step | Product | Roughly |
|---|---|---|
| Dependency scan | Open Source | one test per manifest found; one per repository for multi-module Maven |
| Snapshot (`monitor`) | Open Source | one per manifest |
| Code scan | Code | one per repository |

The usage bars in the app count only the scans this app ran. Snyk keeps the official count in your account.

## Privacy

- A dependency scan sends Snyk the list of packages and versions, not your source code.
- A **code scan uploads your source code** to Snyk for analysis. Turn **Code** off for a repository if that is not allowed for it.
- A snapshot (`monitor`) stores the dependency tree in your Snyk account so Snyk can alert you about new vulnerabilities.

## Build from source

```
git clone https://github.com/bodco/snyk-desk.git
cd snyk-desk
swift test
scripts/make-app.sh 0.1.0    # dist/Snyk Desk.app and dist/SnykDesk-0.1.0.zip
```

Requires Xcode 16 or newer (Swift 5.10+). The core logic (`Sources/SnykDeskCore`) has unit tests; the UI is in `Sources/SnykDesk`.

## Releases

Pushing a tag `v*` makes GitHub Actions build, test and publish a release with the zip. See [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE)
