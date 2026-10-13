import Foundation
import Security
import CryptoKit
import Darwin

// An immutable, locally signed child owns the Keychain item. App updates never
// replace or re-sign the installed child. No receiver secret is written to disk.
enum CredentialBrokerClient {
    static let identifier = "com.stan.micbridge.credentials"
    struct Context {
        let anchor: URL
        let directory: URL
        let appURL: URL
        let bundledBrokerURL: URL
        let signingContext: LocalSigning.Context
        #if BROKER_TESTING
        var testKeychain: String? = nil
        var testExpectedParentPath: String? = nil
        #endif
    }
    private struct Manifest: Codable {
        let schema: Int
        let sha256: String
        let certificateSHA1: String
    }
    struct Failure: Error, LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }
    static func productionContext() -> Context {
        let app = Bundle.main.bundleURL
        let home = FileManager.default.homeDirectoryForCurrentUser
        return Context(anchor: home,
            directory: home.appendingPathComponent("Library/Application Support/StanMicBridge/CredentialBroker"),
            appURL: app, bundledBrokerURL: app.appendingPathComponent("Contents/Helpers/StanMicCredentialBroker"),
            signingContext: LocalSigning.productionContext())
    }
    private static func require(_ value: Bool, _ message: String) throws {
        if !value { throw Failure(message: message) }
    }
    private static func privateFile(_ path: URL, maximum: Int64) throws {
        var info = stat()
        try require(lstat(path.path, &info) == 0 && info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG)
            && info.st_uid == geteuid() && info.st_mode & 0o077 == 0 && info.st_nlink == 1
            && info.st_size > 0 && info.st_size <= maximum,
            "固定鑰匙圈輔助程式的檔案遺失或權限不正確；已停止讀寫，未重新建立身分。")
    }
    private static func digest(_ path: URL) throws -> String {
        SHA256.hash(data: try Data(contentsOf: path)).map { String(format: "%02x", $0) }.joined()
    }
    private static func validate(_ folder: URL, config: LocalSigning.Configuration) throws -> URL {
        var info = stat()
        try require(lstat(folder.path, &info) == 0 && info.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR)
            && info.st_uid == geteuid() && info.st_mode & 0o077 == 0,
            "固定鑰匙圈輔助程式目錄不安全；已停止讀寫。")
        let executable = folder.appendingPathComponent("StanMicCredentialBroker")
        let manifestURL = folder.appendingPathComponent("manifest.json")
        try privateFile(manifestURL, maximum: 4096)
        try privateFile(executable, maximum: 32 * 1024 * 1024)
        let manifest = try JSONDecoder().decode(Manifest.self, from: Data(contentsOf: manifestURL))
        try require(manifest.schema == 1 && manifest.certificateSHA1 == config.certificateSHA1.lowercased()
            && manifest.sha256 == (try digest(executable)),
            "固定鑰匙圈輔助程式已變更；為保留原有授權，未自動替換或重新簽章。")
        try LocalSigning.verifyPinned(executable, config: config, identifier: identifier)
        return executable
    }
    @discardableResult static func prepare(context: Context) throws -> URL {
        guard let config = try LocalSigning.loadConfiguration(context.signingContext) else {
            throw Failure(message: "固定鑰匙圈輔助程式需要既有的本機固定簽章身分。")
        }
        try LocalSigning.verifyPinned(context.appURL, config: config, identifier: LocalSigning.appIdentifier)
        let state = LocalSigning.Context(anchor: context.anchor, directory: context.directory)
        guard let directory = try LocalSigning.stateDirectory(state, create: true) else {
            throw Failure(message: "無法開啟固定鑰匙圈輔助程式目錄。")
        }
        let lockPath = directory.appendingPathComponent("bootstrap.lock")
        let lock = open(lockPath.path, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
        try require(lock >= 0, "無法鎖定鑰匙圈輔助程式設定。")
        defer { close(lock) }
        var lockInfo = stat()
        try require(fstat(lock, &lockInfo) == 0 && lockInfo.st_uid == geteuid()
            && lockInfo.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG) && lockInfo.st_mode & 0o077 == 0
            && lockInfo.st_nlink == 1 && flock(lock, LOCK_EX | LOCK_NB) == 0,
            "另一個程式正在設定固定鑰匙圈輔助程式；請稍後重試。")
        defer { flock(lock, LOCK_UN) }
        let destination = directory.appendingPathComponent("v1")
        let marker = directory.appendingPathComponent("installed-v1")
        var info = stat()
        if lstat(destination.path, &info) == 0 {
            let result = try validate(destination, config: config)
            if lstat(marker.path, &info) != 0 {
                try require(errno == ENOENT, "無法檢查鑰匙圈輔助程式安裝紀錄。")
                try Data("1".utf8).write(to: marker, options: .withoutOverwriting)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: marker.path)
            } else { try privateFile(marker, maximum: 16) }
            return result
        }
        try require(errno == ENOENT, "無法檢查固定鑰匙圈輔助程式。")
        try require(lstat(marker.path, &info) != 0 && errno == ENOENT,
            "先前安裝的鑰匙圈輔助程式已遺失；未建立替代身分，請還原原有檔案。")
        // The seed is sealed by the validated running app. Later updates may
        // bundle a different seed, but an installed v1 is never refreshed.
        try LocalSigning.checkCode(context.bundledBrokerURL)
        let staging = directory.appendingPathComponent("bootstrap-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: staging, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: staging) }
        let executable = staging.appendingPathComponent("StanMicCredentialBroker")
        try FileManager.default.copyItem(at: context.bundledBrokerURL, to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        try LocalSigning.sign(executable, identifier: identifier, config: config)
        let manifest = Manifest(schema: 1, sha256: try digest(executable), certificateSHA1: config.certificateSHA1.lowercased())
        let manifestURL = staging.appendingPathComponent("manifest.json")
        try JSONEncoder().encode(manifest).write(to: manifestURL, options: .withoutOverwriting)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: manifestURL.path)
        _ = try validate(staging, config: config)
        try FileManager.default.moveItem(at: staging, to: destination)
        try Data("1".utf8).write(to: marker, options: .withoutOverwriting)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: marker.path)
        return try validate(destination, config: config)
    }
    private static func uniqueCode(_ code: SecStaticCode) throws -> Data {
        var info: CFDictionary?
        try LocalSigning.check(SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info), "Read broker identity")
        guard let fields = info as? [String: Any], let unique = fields[kSecCodeInfoUnique as String] as? Data,
              let flags = fields[kSecCodeInfoFlags as String] as? NSNumber, flags.uint32Value & 0x10000 != 0 else {
            throw Failure(message: "鑰匙圈輔助程式缺少 Hardened Runtime 保護。")
        }
        return unique
    }
    private static func authenticateChild(_ process: Process, requirement: SecRequirement, unique: Data) throws {
        try require(process.isRunning, "鑰匙圈輔助程式未正常啟動。")
        var guest: SecCode?
        try LocalSigning.check(SecCodeCopyGuestWithAttributes(nil,
            [kSecGuestAttributePid as String: process.processIdentifier] as CFDictionary, [], &guest), "Identify broker process")
        guard let child = guest else { throw Failure(message: "無法識別鑰匙圈輔助程式。") }
        try LocalSigning.check(SecCodeCheckValidity(child, [], requirement), "Authenticate broker process")
        var staticChild: SecStaticCode?
        try LocalSigning.check(SecCodeCopyStaticCode(child, [], &staticChild), "Read launched broker code")
        guard let childCode = staticChild else { throw Failure(message: "無法識別鑰匙圈輔助程式程式碼。") }
        try require(try uniqueCode(childCode) == unique && process.isRunning, "鑰匙圈輔助程式身分與已驗證版本不符。")
    }
    private static func line(_ handle: FileHandle, process: Process, timeout: TimeInterval) throws -> Data {
        let descriptor = handle.fileDescriptor
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        var result = Data()
        while ProcessInfo.processInfo.systemUptime < deadline {
            var descriptorState = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
            let ready = poll(&descriptorState, 1, 100)
            if ready < 0 && errno == EINTR { continue }
            try require(ready >= 0, "鑰匙圈輔助程式通訊失敗。")
            if ready == 0 { continue }
            var byte: UInt8 = 0
            let count = Darwin.read(descriptor, &byte, 1)
            if count < 0 && errno == EINTR { continue }
            try require(count == 1, "鑰匙圈輔助程式在完成前結束；未改用其他儲存方式。")
            if byte == 10 { return result }
            result.append(byte)
            try require(result.count <= 16384, "鑰匙圈輔助程式回應超過大小限制。")
        }
        throw Failure(message: "等待鑰匙圈授權逾時；請重新啟動 App 後重試。")
    }
    static func perform(_ operation: String, payload: Data? = nil, context supplied: Context? = nil) throws -> Data? {
        let context = supplied ?? productionContext()
        let executable = try prepare(context: context)
        let code = try LocalSigning.staticCode(executable)
        let unique = try uniqueCode(code)
        let requirement = try LocalSigning.designatedRequirement(executable)
        let process = Process()
        let input = Pipe(), output = Pipe()
        process.executableURL = executable
        process.arguments = []
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        process.environment = ["PATH": "/usr/bin:/bin", "HOME": FileManager.default.homeDirectoryForCurrentUser.path]
        #if BROKER_TESTING
        process.environment?["BROKER_TEST_EXPECTED_PARENT_PATH"] = context.testExpectedParentPath
        #endif
        try process.run()
        defer {
            try? input.fileHandleForWriting.close()
            try? output.fileHandleForReading.close()
            if process.isRunning {
                process.terminate()
                let deadline = ProcessInfo.processInfo.systemUptime + 2
                while process.isRunning && ProcessInfo.processInfo.systemUptime < deadline { Thread.sleep(forTimeInterval: 0.01) }
                if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            }
        }
        let ready = try JSONDecoder().decode(CredentialBrokerWire.Response.self,
            from: line(output.fileHandleForReading, process: process, timeout: 15))
        try require(ready.schema == 1 && ready.status == errSecSuccess && ready.data == nil,
            "鑰匙圈輔助程式通訊版本不相容。")
        // Authenticate the actual launched process before sending any token.
        try authenticateChild(process, requirement: requirement, unique: unique)
        var request = CredentialBrokerWire.Request(schema: 1, operation: operation, payload: payload)
        #if BROKER_TESTING
        request.testKeychain = context.testKeychain
        #endif
        let bytes = try JSONEncoder().encode(request)
        try require(bytes.count <= 16384, "連線資料超過大小限制。")
        _ = fcntl(input.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1)
        try input.fileHandleForWriting.write(contentsOf: bytes)
        try input.fileHandleForWriting.close()
        let response = try JSONDecoder().decode(CredentialBrokerWire.Response.self,
            from: line(output.fileHandleForReading, process: process, timeout: 120))
        try require(response.schema == 1, "鑰匙圈輔助程式通訊版本不相容。")
        if response.status == errSecItemNotFound && operation == "load" { return nil }
        guard response.status == errSecSuccess else {
            throw Failure(message: "鑰匙圈未完成授權或讀寫（\(response.status)）；請確認登入鑰匙圈已解鎖後重試。")
        }
        return response.data
    }
}
