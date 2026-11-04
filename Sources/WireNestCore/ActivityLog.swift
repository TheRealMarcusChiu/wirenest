import Foundation

public struct ActivityLogEntry: Identifiable, Equatable {
    public let id: Int
    public let date: Date
    public let context: String
    public let message: String
}

/// What has gone wrong this session, in memory only. A condition reported on every status poll is one
/// entry, and it can be logged again only after it has cleared. Text is redacted before it is stored and when rendered.
public struct ActivityLog: Equatable {
    public static let capacity = 200
    public static let maxMessageLength = 2000

    public private(set) var entries: [ActivityLogEntry] = []
    private var current: [String: String] = [:]
    private var nextID = 0

    public init() {}

    /// `source` identifies the condition. A nil message means it has cleared.
    public mutating func report(_ message: String?, source: String, context: String, now: Date) {
        guard let message else {
            current[source] = nil
            return
        }
        guard current[source] != message else { return }
        current[source] = message

        // Redacted before cutting, as a cut could leave a key too short for the redaction to recognise.
        var clean = redactSecrets(message).components(separatedBy: .newlines).joined(separator: " ")
        if clean.count > Self.maxMessageLength { clean = String(clean.prefix(Self.maxMessageLength)) + "…" }
        entries.append(ActivityLogEntry(id: nextID, date: now, context: redactSecrets(context), message: clean))
        nextID += 1
        if entries.count > Self.capacity { entries.removeFirst(entries.count - Self.capacity) }
    }

    /// Conditions still in effect stay known, so clearing does not immediately relist them.
    public mutating func clear() {
        entries = []
    }

    /// One line per entry. The Logs pane shows this exact text, and Copy Logs copies it.
    public func text(timeZone: TimeZone = .current) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = timeZone
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return entries.map { redactSecrets("\(formatter.string(from: $0.date))  \($0.context)  \($0.message)") }.joined(separator: "\n")
    }
}

/// A few words for the menu. The full text stays in the log.
public func shortFailure(_ message: String) -> String {
    let limit = 60
    if message.contains("no proven physical-LAN") { return "Route safety check failed" }
    let clean = redactSecrets(message)
    let firstLine = clean.split(whereSeparator: \.isNewline).first.map(String.init) ?? clean
    // A sentence ends at a full stop before a space, so an address such as 10.0.0.1 stays whole.
    let sentence = firstLine.range(of: ". ").map { String(firstLine[..<$0.lowerBound]) } ?? firstLine
    let trimmed = sentence.hasSuffix(".") ? String(sentence.dropLast()) : sentence
    return trimmed.count <= limit ? trimmed : String(trimmed.prefix(limit - 1)) + "…"
}
