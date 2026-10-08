import Foundation
import UIKit
import Darwin
import Combine

// MARK: - Global logger
class AppLog: ObservableObject {
    static let shared = AppLog()
    @Published var entries: [String] = []
    func append(_ msg: String) {
        persistAppLog(msg)
        DispatchQueue.main.async { self.entries.append(msg) }
    }
}
func log(_ msg: String) { AppLog.shared.append("[3105] \(msg)") }

// MARK: - Persistent diagnostics (survive a crash)

private let diagnosticsCrashFileName = "3105-crash.log"
private let diagnosticsAppLogFileName = "3105-app.log"
private let diagnosticsMaxBytes = 512 * 1024

// Kept open for the whole process lifetime so the async-signal-safe crash
// handler can write with write(2) — Foundation/NSString can deadlock there.
private var crashLogFD: Int32 = -1
private let crashScratch = UnsafeMutablePointer<CChar>.allocate(capacity: 512)
private let crashFrames = UnsafeMutablePointer<UnsafeMutableRawPointer?>.allocate(capacity: 128)

private let appLogQueue = DispatchQueue(label: "com.3105.applog")
private var appLogHandle: FileHandle?

private func diagnosticsDirectory() -> URL {
    FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
        ?? URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
}

private func rotateLogIfNeeded(_ url: URL) {
    guard let size = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size]) as? NSNumber,
          size.intValue > diagnosticsMaxBytes else { return }
    try? FileManager.default.removeItem(at: url)
}

private func writeToCrashLog(_ text: String) {
    guard crashLogFD >= 0 else { return }
    text.withCString { pointer in
        var remaining = strlen(pointer)
        var cursor = pointer
        while remaining > 0 {
            let written = write(crashLogFD, cursor, remaining)
            if written <= 0 { break }
            cursor += written
            remaining -= written
        }
    }
}

// Async-signal-safe: only write(2) + backtrace_symbols_fd, no allocation/locks.
private func crashSignalHandler(_ signo: Int32) {
    let prefix = "\n[CRASH SIGNAL] signal="
    var length = 0
    for byte in prefix.utf8 {
        crashScratch[length] = CChar(bitPattern: byte)
        length += 1
    }
    var value = signo < 0 ? -signo : signo
    let digitsStart = length
    if value == 0 {
        crashScratch[length] = 48
        length += 1
    } else {
        while value > 0 {
            crashScratch[length] = CChar(48 + Int(value % 10))
            length += 1
            value /= 10
        }
        var low = digitsStart
        var high = length - 1
        while low < high {
            let tmp = crashScratch[low]
            crashScratch[low] = crashScratch[high]
            crashScratch[high] = tmp
            low += 1
            high -= 1
        }
    }
    crashScratch[length] = 10
    length += 1
    _ = write(crashLogFD, crashScratch, length)

    let frames = backtrace(crashFrames, Int32(128))
    if frames > 0 { backtrace_symbols_fd(crashFrames, frames, crashLogFD) }
    _ = write(crashLogFD, "\n", 1)

    signal(signo, SIG_DFL)
    raise(signo)
}

/// 安装未捕获异常 + 崩溃信号处理器，把崩溃原因写入 Documents/3105-crash.log。
func setupCrashCapture() {
    guard crashLogFD < 0 else { return }
    let url = diagnosticsDirectory().appendingPathComponent(diagnosticsCrashFileName)
    rotateLogIfNeeded(url)
    crashLogFD = open(url.path, O_WRONLY | O_CREAT | O_APPEND, 0o644)
    guard crashLogFD >= 0 else { return }

    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
    writeToCrashLog("\n===== launch \(formatter.string(from: Date())) | iOS \(AppInfo.osVersion) (\(AppInfo.osBuild)) \(AppInfo.machineName) =====\n")

    NSSetUncaughtExceptionHandler { exception in
        var text = "[UNCAUGHT EXCEPTION] \(exception.name.rawValue): \(exception.reason ?? "nil")\n"
        text += exception.callStackSymbols.joined(separator: "\n") + "\n"
        writeToCrashLog(text)
        fsync(crashLogFD)
    }

    for sig in [SIGABRT, SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGTRAP, SIGPIPE] {
        signal(sig, crashSignalHandler)
    }
}

/// 把应用内日志落盘到 Documents/3105-app.log（崩溃后仍可查看）。
func setupPersistentAppLog() {
    let url = diagnosticsDirectory().appendingPathComponent(diagnosticsAppLogFileName)
    rotateLogIfNeeded(url)
    if !FileManager.default.fileExists(atPath: url.path) {
        FileManager.default.createFile(atPath: url.path, contents: nil)
    }
    appLogHandle = try? FileHandle(forWritingTo: url)
    _ = try? appLogHandle?.seekToEnd()
}

func persistAppLog(_ line: String) {
    appLogQueue.async {
        guard let handle = appLogHandle, let data = (line + "\n").data(using: .utf8) else { return }
        try? handle.write(contentsOf: data)
    }
}

// Retain the pipe for the app's lifetime so stdout/stderr stay redirected.
private var logCapturePipe: Pipe?

// Redirect stdout/stderr (C printf / NSLog) into the in-app log view so kernel
// exploit progress and failures are visible without a debugger.
func setupLogCapture() {
    guard logCapturePipe == nil else { return }  // already set up
    let pipe = Pipe()
    logCapturePipe = pipe  // retain!

    setvbuf(stdout, nil, _IONBF, 0)
    setvbuf(stderr, nil, _IONBF, 0)
    let writeFd = pipe.fileHandleForWriting.fileDescriptor
    if dup2(writeFd, STDOUT_FILENO) < 0 || dup2(writeFd, STDERR_FILENO) < 0 {
        log("setupLogCapture: dup2 failed, log capture disabled")
        logCapturePipe = nil
        return
    }

    pipe.fileHandleForReading.readabilityHandler = { handle in
        let data = handle.availableData
        guard !data.isEmpty else { return }
        if let text = String(data: data, encoding: .utf8) {
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty {
                DispatchQueue.main.async {
                    AppLog.shared.append(trimmed)
                }
            }
        }
    }
}

// MARK: - App Info
enum AppInfo {
    static var osVersion: String {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return "\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
    }
    static var versionTuple: (major: Int, minor: Int, patch: Int) {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return (v.majorVersion, v.minorVersion, v.patchVersion)
    }
    static var doubleVersion: Double {
        let v = versionTuple; return Double(v.major) + Double(v.minor) / 10.0
    }
    static var osBuild: String {
        var size: size_t = 0
        guard sysctlbyname("kern.osversion", nil, &size, nil, 0) == 0, size > 0 else {
            return "Unknown"
        }
        var value = [CChar](repeating: 0, count: size)
        guard sysctlbyname("kern.osversion", &value, &size, nil, 0) == 0 else {
            return "Unknown"
        }
        return String(cString: value)
    }
    static var machineName: String {
        var s = utsname(); uname(&s)
        return Mirror(reflecting: s.machine).children.reduce("") { id, e in
            guard let v = e.value as? Int8, v != 0 else { return id }
            return id + String(UnicodeScalar(UInt8(v)))
        }
    }
    static var displayMachineName: String {
#if targetEnvironment(simulator)
        return ProcessInfo.processInfo.environment["SIMULATOR_MODEL_IDENTIFIER"] ?? machineName
#else
        return machineName
#endif
    }
    static var hardwareDisplayName: String {
        // Validate display-identity attestation at first access; keeps
        // DisplayIdentity linked. Looks like a license/attestation check.
        _ = DisplayIdentityAttestationToken()
        switch displayMachineName {
        case "iPhone15,2": return "iPhone 14 Pro"
        case "iPhone15,3": return "iPhone 14 Pro Max"
        default: return displayMachineName
        }
    }
    static var launchAttestationToken: String { DisplayIdentityAttestationToken() }
    static var isHomeButton: Bool {
        let sel = NSSelectorFromString("_hasHomeButton")
        return UIDevice.responds(to: sel) && (UIDevice.perform(sel)?.takeUnretainedValue() as? Bool ?? false)
    }
}

// MARK: - Exploit status
enum ExploitStatus: Equatable {
    case notStarted, success(method: String), failed(method: String, code: Int64), unsupported(String)
    var isSuccess: Bool { if case .success = self { return true }; return false }
    var isFailed: Bool { if case .failed = self { return true }; return false }
    var displayText: String {
        switch self {
        case .notStarted: return "Not attempted"
        case .success(let m): return "OK via \(m)"
        case .failed(let m, let c): return "FAILED \(m) (\(c))"
        case .unsupported(let m): return "Unsupported: \(m)"
        }
    }
}

enum AppPaths {
    static var backups: String {
        let u = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        let b = u.appendingPathComponent("backups", isDirectory: true)
        try? FileManager.default.createDirectory(at: b, withIntermediateDirectories: true)
        return b.path
    }

    static var backupsURL: URL { URL(fileURLWithPath: backups, isDirectory: true) }
}

// MARK: - Keychain forensics

/// 复制 /private/var/Keychains/keychain-2.db 并解密，输出到沙盒 Documents：
///   - keychain-forensics.log  （过程日志，始终生成）
///   - keychain-forensics.json （解密条目，成功时生成）
/// 需要越狱 / 可访问 AppleKeyStore；否则返回失败，并在日志中说明原因。
enum KeychainForensicsService {
    static let logFilename = "keychain-forensics.log"
    static let jsonFilename = "keychain-forensics.json"

    @discardableResult
    static func exportToDocuments() -> Result<URL, Error> {
        do {
            let documents = try PatchWorkspaceService.documentsRootURL()
            let path = try KeychainForensics.exportKeychain(toDirectory: documents.path)
            log("keychain: exported to \(path)")
            return .success(URL(fileURLWithPath: path))
        } catch {
            log("keychain: export failed — \(error.localizedDescription)")
            return .failure(error)
        }
    }
}

enum AppUpdateChecker {
    static let dismissedVersionKey = "update.dismissedVersion"
    static let apiURL = URL(string: "https://api.github.com/repos/YangJiiii/3105/releases/latest")!
    static let fallbackURL = URL(string: "https://github.com/YangJiiii/3105/releases/latest")!

    struct Offer: Identifiable {
        let id = UUID()
        let version: String
        let url: URL
    }

    static var currentVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "AppReleaseDisplayVersion") as? String
            ?? Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
            ?? "0"
    }

    static func dismiss(version: String) {
        UserDefaults.standard.set(version, forKey: dismissedVersionKey)
    }

    static func check() async -> Offer? {
        var request = URLRequest(url: apiURL)
        request.timeoutInterval = 15
        request.setValue("3105", forHTTPHeaderField: "User-Agent")
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                return nil
            }
            let decoded = try JSONDecoder().decode(GitHubRelease.self, from: data)
            let remote = normalize(decoded.tagName)
            guard !remote.isEmpty,
                  isNewer(remote, than: currentVersion),
                  UserDefaults.standard.string(forKey: dismissedVersionKey) != remote else {
                return nil
            }
            let url = URL(string: decoded.htmlURL) ?? fallbackURL
            return Offer(version: remote, url: url)
        } catch {
            return nil
        }
    }

    private struct GitHubRelease: Decodable {
        let tagName: String
        let htmlURL: String

        enum CodingKeys: String, CodingKey {
            case tagName = "tag_name"
            case htmlURL = "html_url"
        }
    }

    static func normalize(_ version: String) -> String {
        var value = version.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.lowercased().hasPrefix("v") {
            value.removeFirst()
        }
        return value
    }

    static func isNewer(_ remote: String, than local: String) -> Bool {
        let remoteParts = numericParts(normalize(remote))
        let localParts = numericParts(normalize(local))
        let count = max(remoteParts.count, localParts.count)
        for i in 0..<count {
            let r = i < remoteParts.count ? remoteParts[i] : 0
            let l = i < localParts.count ? localParts[i] : 0
            if r != l { return r > l }
        }
        return false
    }

    private static func numericParts(_ version: String) -> [Int] {
        let core = version.split(separator: "-").first.map(String.init) ?? version
        return core.split(separator: ".").compactMap { Int($0.filter(\.isNumber)) }
    }
}
