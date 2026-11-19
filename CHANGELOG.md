# Changelog

## 0.2.4 - 2026-11-20

- Report button next to Scan now: a full report of the vulnerabilities shown (filters apply) as PDF, Markdown or HTML, grouped by severity, with every detail the scan has (location, dependency path, CVSS, CWE, CVE, fix, Snyk's explanation) and links for deeper analysis (Snyk database, NVD, CWE).
- Dependencies and Code in the header now say how many issues each found, and clicking one filters the list to it.
- Settings: the Repositories section moved to the bottom and collapses (closed by default). The project picker no longer shows a double arrow or a doubled label.
- Clicking a repository card on the dashboard opens it.
- Scan problems are readable: the error line is shown instead of the Docs/Tip/ID footer, and a sub-project Snyk could not read (for example `spikes/m0/requirements.txt`) is named. After a failed Maven scan the launcher also saves Snyk's debug output to `deps.debug.log`.

## 0.2.3 - 2026-11-20

- The release zip now also holds a short "Read me first" with the first-launch steps (EN and UK), like the Pacenote DMG.
- Results are kept locally for good: every finished scan also gets `report.md` (readable, pasteable into Claude) and `summary.json` in its own folder, next to the raw Snyk files. Older scans get them too the next time the app opens. Scan folders are never deleted or overwritten by the app, so logging out, switching Snyk account or removing a repository from the list does not lose any results.
- Snyk account: "Log out" and "Switch account" in Settings. Switch account logs the CLI out and opens the browser login, so you can scan the same repositories with another Snyk account.
- No more "Apple could not verify" on every reinstall. That warning appears for any app downloaded in a browser that is not notarized (notarization needs a paid Apple Developer ID). Two ways around it: `scripts/install.sh` (one `curl` command; curl downloads are not quarantined) and an in-app updater (Settings > Updates, plus a dashboard banner) that downloads the new release itself, swaps the app after it quits and starts it again. The "Check for updates" button sits at the bottom of the sidebar and in the app menu, and becomes "Install <version> and restart" when a new release exists.

## 0.2.2 - 2026-11-20

- Logging: every scan folder now has a `scan.log` with the Snyk version, PATH, `JAVA_HOME`, the versions of java, mvn, node, go and uv, the commands that ran, exit codes and durations. The app keeps its own log in `~/Library/Application Support/SnykDesk/logs/snyk-desk.log` (scans, launcher, tool installs, rotated at 1 MB).
- A failed Maven dependency scan now also runs `mvn dependency:tree` and saves Maven's own error to `maven.log`, because Snyk only says "Cannot build Maven dependency tree". The first Maven error is shown on the repository page.
- Plain hints for the common Snyk errors (Maven 0018, no supported files, missing tool, not signed in).
- A monitor run where the main project was monitored but some sub-project failed is now shown as done with a note, not as an error.
- App icon.
- Every vulnerability now has a link. Snyk Code results carry none, so they link to the CWE page of the weakness (MITRE). Dependency findings still link to the Snyk vulnerability database.
- "Copy to Claude" on the repository page copies a prompt (in Ukrainian) with the repository path and the vulnerabilities shown now, so the severity and type filters decide what goes in. Paste it into a Claude project that has the code.
- A copy icon on every vulnerability: copy its details, copy it with a prompt for Claude, or copy a prompt for all findings of the same type.
- The repository page has "Open scan log", "Open dependencies log", "Open monitor log" and "Show scan folder" buttons, and Settings has "Open app log". The launcher is now v4.

## 0.2.1 - 2026-11-19

- Build tools: setup has a new "Tools" step, and Settings has a "Tools" section. The app reads your repositories, lists which of Java, Maven, Gradle, Node.js, Go and the Xcode Command Line Tools they need, and installs the missing ones with a progress bar. No Terminal, no Homebrew, no admin password: tools are downloaded from the official sites into the app's own folder. Tools you already have are used as they are, and the ones the app installed can be removed.
- A dependency scan of a repository whose build tool is missing no longer ends with the generic `SNYK-CLI-0000` error. The launcher checks first and says which tool to install. The dashboard and the repository page show a warning with an install button.
- The launcher is now v3: it exports `JAVA_HOME` and the PATH of the tools the app installed, so scans from the app and from launchd use them.

## 0.2.0 - 2026-11-19

- Projects: each repository belongs to a project (guessed from its path, editable in Settings). The dashboard and the Projects tab are grouped by project, with a "Scan project" button.
- Scans are now saved next to the launcher by default as `<launcher folder>/<project>/<repository folder>/<timestamp>/`, instead of a hidden folder in Application Support.
- Each repository can use its own results folder: choose it in Settings or on the repository's page, go back to the default, or show it in Finder.
- Scans made with 0.1.0 are still shown in the history.

## 0.1.0 - 2026-11-19

First release.

- Guided setup: launcher folder (detects an existing launcher), Snyk CLI install with progress or detection, repository folders, Snyk login.
- Dashboard with severity totals, a card per repository and empty states.
- Projects view: scan one repository, live progress and log, scan history, findings filtered by type and severity.
- Per repository switches for dependency scan, code scan and `snyk monitor`.
- Daily or weekly schedule through launchd, with a notification after scheduled scans.
- Local estimate of monthly Free plan test usage; aggregated Maven scans.
- Menu bar item with totals and "Scan all now".
