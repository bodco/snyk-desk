# Changelog

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
