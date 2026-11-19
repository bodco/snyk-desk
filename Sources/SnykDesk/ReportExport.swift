import AppKit
import SnykDeskCore

enum ReportFormat: String, CaseIterable {
    case pdf = "PDF", markdown = "Markdown", html = "HTML"

    var fileExtension: String {
        switch self {
        case .pdf: return "pdf"
        case .markdown: return "md"
        case .html: return "html"
        }
    }
}

enum ReportExport {
    /// Asks where to save, writes the report and shows it in Finder. Returns an error text on failure.
    @MainActor
    static func save(format: ReportFormat, findings: [Finding], run: ScanRun, context: ReportContext) -> String? {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "\(context.repo)-snyk-\(run.id).\(format.fileExtension)"
        panel.directoryURL = run.directory
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return nil }
        do {
            switch format {
            case .markdown:
                try ReportBuilder.markdown(findings: findings, run: run, context: context)
                    .write(to: url, atomically: true, encoding: .utf8)
            case .html:
                try ReportBuilder.html(findings: findings, run: run, context: context)
                    .write(to: url, atomically: true, encoding: .utf8)
            case .pdf:
                try writePDF(html: ReportBuilder.html(findings: findings, run: run, context: context), to: url)
            }
            NSWorkspace.shared.activateFileViewerSelecting([url])
            return nil
        } catch {
            return "Could not save the report: \(error.localizedDescription)"
        }
    }

    /// Lays the HTML out as paginated A4 text and prints it to a PDF file.
    @MainActor
    static func writePDF(html: String, to url: URL) throws {
        guard let data = html.data(using: .utf8),
              let text = NSAttributedString(html: data, options: [.characterEncoding: String.Encoding.utf8.rawValue],
                                            documentAttributes: nil) else {
            throw DeskError("The report could not be laid out.")
        }
        let info = NSPrintInfo()
        info.paperSize = NSSize(width: 595, height: 842)
        info.topMargin = 40
        info.bottomMargin = 40
        info.leftMargin = 40
        info.rightMargin = 40
        info.jobDisposition = .save
        info.dictionary()[NSPrintInfo.AttributeKey.jobSavingURL] = url
        let width = info.paperSize.width - info.leftMargin - info.rightMargin
        let view = NSTextView(frame: NSRect(x: 0, y: 0, width: width, height: 100))
        view.textContainer?.containerSize = NSSize(width: width, height: .greatestFiniteMagnitude)
        view.textContainer?.widthTracksTextView = true
        view.isVerticallyResizable = true
        view.textStorage?.setAttributedString(text)
        view.layoutManager?.ensureLayout(for: view.textContainer!)
        let used = view.layoutManager?.usedRect(for: view.textContainer!) ?? .zero
        view.setFrameSize(NSSize(width: width, height: max(used.height + 20, 100)))
        let operation = NSPrintOperation(view: view, printInfo: info)
        operation.showsPrintPanel = false
        operation.showsProgressPanel = false
        guard operation.run(), FileManager.default.fileExists(atPath: url.path) else {
            throw DeskError("macOS could not write the PDF.")
        }
    }
}
