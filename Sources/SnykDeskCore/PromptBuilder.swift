import Foundation

/// Builds the text the "Copy" buttons put on the clipboard, ready to paste into a Claude project
/// that has access to the code.
public enum PromptBuilder {
    /// The most findings written out in full in one prompt. The rest are listed by title only.
    public static let fullLimit = 40

    public static func findingText(_ finding: Finding) -> String {
        var lines = ["\(finding.title) [\(finding.severity.label), \(finding.kind == .dependency ? "dependency" : "code")]",
                     "ID: \(finding.issueId)",
                     "Where: \(finding.location)"]
        if !finding.detail.isEmpty {
            lines.append(finding.kind == .dependency ? "Dependency path: \(finding.detail)" : "Snyk says: \(finding.detail)")
        }
        if let cwe = finding.cwe, !cwe.isEmpty { lines.append("CWE: \(cwe.joined(separator: ", "))") }
        if let fix = finding.fix { lines.append("Fix: \(fix)") }
        if let advice = finding.advice { lines.append("About: \(advice)") }
        if let url = finding.url { lines.append("Link: \(url)") }
        return lines.joined(separator: "\n")
    }

    public static func singlePrompt(_ finding: Finding, repo: String, project: String, path: String) -> String {
        """
        Розбери одну вразливість зі Snyk у репозиторії "\(repo)" (проєкт \(project)).
        Код лежить тут: \(path)

        \(findingText(finding))

        Що зробити:
        1. Відкрий вказаний код і перевір, чи вразливість справжня, чи це хибне спрацювання. Поясни чому.
        2. Якщо справжня: оціни реальний ризик саме для цього застосунку (звідки приходять дані, хто їх контролює).
        3. Запропонуй мінімальну правку і покажи діф. Нічого не коміть і не пуш без мого дозволу.
        4. Скажи, як перевірити, що правка працює.
        Не друкуй секрети, якщо вони трапляться в коді.
        """
    }

    public static func repoPrompt(findings: [Finding], repo: String, project: String, path: String,
                                  filter: String, scanDate: String, sameIssue: String? = nil) -> String {
        let counts = SeverityCounts.of(findings)
        let ordered = ResultParser.sorted(findings)
        let full = ordered.prefix(fullLimit)
        let rest = ordered.dropFirst(fullLimit)
        var body = full.enumerated()
            .map { "\($0.offset + 1). " + findingText($0.element).replacingOccurrences(of: "\n", with: "\n   ") }
            .joined(separator: "\n\n")
        if !rest.isEmpty {
            body += "\n\nЩе \(rest.count) без деталей (відкрий скан Snyk Desk або запусти snyk повторно, якщо потрібні подробиці):\n"
            body += rest.map { "- [\($0.severity.label)] \($0.title) - \($0.location)" }.joined(separator: "\n")
        }
        let scope = sameIssue.map { "Усі вразливості одного типу: \($0)." } ?? "Фільтр: \(filter)."
        return """
        Розбери вразливості зі Snyk у репозиторії "\(repo)" (проєкт \(project)).
        Код лежить тут: \(path)
        Скан: \(scanDate). \(scope)
        Усього: \(findings.count) (Critical \(counts.critical), High \(counts.high), Medium \(counts.medium), Low \(counts.low)).

        Що зробити:
        1. Іди від найкритичніших. Для кожної перевір у коді, чи вона справжня, чи це хибне спрацювання, і поясни чому.
        2. Однакові за суттю (той самий пакет або те саме правило) згрупуй і розбери разом.
        3. Для справжніх: реальний ризик саме для цього застосунку і мінімальна правка. Для залежностей: до якої версії оновити і чи не ламає це збірку.
        4. Дай підсумок: що виправляємо зараз, що відкладаємо, що ігноруємо і чому.
        5. Нічого не коміть, не пуш і не змінюй без мого дозволу: спершу покажи плани і діфи.
        Не друкуй секрети, якщо вони трапляться в коді.

        Вразливості:

        \(body)
        """
    }
}
