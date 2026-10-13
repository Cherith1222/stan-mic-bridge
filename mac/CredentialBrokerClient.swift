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
        var testPinnedSHA256: String? = nil
        var testPinnedCodeHashes: [String]? = nil
        #endif
    }
    private struct Manifest: Codable, Equatable {
        let schema: Int
        let sha256: String
        let certificateSHA1: String
        let codeHashes: [String]
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
    private static let pinName = "CredentialBrokerPin.json"
    private static func validCodeHashes(_ hashes: [String]) -> Bool {
        !hashes.isEmpty && hashes.count <= 2 && Set(hashes).count == hashes.count
            && hashes.allSatisfy { ($0.count == 40 || $0.count == 64) && $0.allSatisfy({ "0123456789abcdef".contains($0) }) }
    }
    private static func pinURL(_ app: URL) -> URL {
        app.appendingPathComponent("Contents/Resources").appendingPathComponent(pinName)
    }
    private static func readPin(_ app: URL, config: LocalSigning.Configuration) throws -> Manifest? {
        let path = pinURL(app)
        var info = stat()
        if lstat(path.path, &info) != 0 {
            try require(errno == ENOENT, "無法檢查 App 內的固定鑰匙圈身分。")
            return nil
        }
        try require(info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG) && info.st_size > 0 && info.st_size <= 4096,
                    "App 內的固定鑰匙圈身分格式不正確。")
        let data = try Data(contentsOf: path)
        let fields = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        let pin = try JSONDecoder().decode(Manifest.self, from: data)
        try require(Set(fields?.keys.map { $0 } ?? []) == Set(["schema", "sha256", "certificateSHA1", "codeHashes"])
            && pin.schema == 1 && pin.certificateSHA1 == config.certificateSHA1.lowercased()
            && pin.sha256.count == 64 && pin.sha256.allSatisfy({ "0123456789abcdef".contains($0) })
            && validCodeHashes(pin.codeHashes),
            "App 內的固定鑰匙圈身分不符合本機簽章。")
        return pin
    }
    private static func trustedPin(_ context: Context, config: LocalSigning.Configuration) throws -> Manifest {
        #if BROKER_TESTING
        if let hash = context.testPinnedSHA256 {
            try require(hash.count == 64 && hash.allSatisfy({ "0123456789abcdef".contains($0) }), "Invalid test broker pin")
            guard let hashes = context.testPinnedCodeHashes, validCodeHashes(hashes) else {
                throw Failure(message: "Missing literal test broker code hashes")
            }
            return Manifest(schema: 1, sha256: hash, certificateSHA1: config.certificateSHA1.lowercased(), codeHashes: hashes)
        }
        #endif
        guard let pin = try readPin(context.appURL, config: config) else {
            throw Failure(message: "尚未建立 App 內的固定鑰匙圈身分。請先使用來源安裝程式 install.command --local-signing 設定一次；未自動採用外部檔案。")
        }
        return pin
    }
    private static func validate(_ folder: URL, config: LocalSigning.Configuration, pin: Manifest) throws -> URL {
        var info = stat()
        try require(lstat(folder.path, &info) == 0 && info.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR)
            && info.st_uid == geteuid() && info.st_mode & 0o077 == 0,
            "固定鑰匙圈輔助程式目錄不安全；已停止讀寫。")
        let executable = folder.appendingPathComponent("StanMicCredentialBroker")
        let manifestURL = folder.appendingPathComponent("manifest.json")
        try privateFile(manifestURL, maximum: 4096)
        try privateFile(executable, maximum: 32 * 1024 * 1024)
        let manifest = try JSONDecoder().decode(Manifest.self, from: Data(contentsOf: manifestURL))
        try require(manifest == pin && manifest.schema == 1 && manifest.certificateSHA1 == config.certificateSHA1.lowercased()
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
        // Trust comes from this already-validated app's sealed resource, never
        // from the writable broker manifest. No production bootstrap on load.
        let pin = try trustedPin(context, config: config)
        let state = LocalSigning.Context(anchor: context.anchor, directory: context.directory)
        guard let directory = try LocalSigning.stateDirectory(state, create: false) else {
            throw Failure(message: "固定鑰匙圈輔助程式已遺失；請還原原有檔案，未建立替代身分。")
        }
        try privateFile(directory.appendingPathComponent("installed-v1"), maximum: 16)
        return try validate(directory.appendingPathComponent("v1"), config: config, pin: pin)
    }

    // Only explicit source installation may bootstrap. A pre-existing broker
    // without an authenticated app pin is never adopted, even if well signed.
    private static func bootstrap(context: Context, config: LocalSigning.Configuration,
                                  commit: (Manifest) throws -> Void) throws -> URL {
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
        try require(lstat(destination.path, &info) != 0 && errno == ENOENT,
            "已有外部鑰匙圈輔助程式但缺少 App 內的可信身分；未採用、覆寫或重新簽章。")
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
        let manifest = Manifest(schema: 1, sha256: try digest(executable), certificateSHA1: config.certificateSHA1.lowercased(),
                                codeHashes: try codeHashes(executable))
        let manifestURL = staging.appendingPathComponent("manifest.json")
        try JSONEncoder().encode(manifest).write(to: manifestURL, options: .withoutOverwriting)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: manifestURL.path)
        _ = try validate(staging, config: config, pin: manifest)
        try FileManager.default.moveItem(at: staging, to: destination)
        var createdMarker = false
        do {
            try Data("1".utf8).write(to: marker, options: .withoutOverwriting)
            createdMarker = true
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: marker.path)
            try commit(manifest)
            return try validate(destination, config: config, pin: manifest)
        } catch {
            // Roll back only the broker created by this invocation, while still
            // holding the bootstrap lock. Never remove a changed installation.
            if (try? validate(destination, config: config, pin: manifest)) != nil {
                try? FileManager.default.removeItem(at: destination)
                if createdMarker { try? FileManager.default.removeItem(at: marker) }
            }
            throw error
        }
    }
    private static func installerContext(app: URL, context: LocalSigning.Context) -> Context {
        let production = LocalSigning.productionContext()
        let directory = context.directory.standardizedFileURL == production.directory.standardizedFileURL
            && context.anchor.standardizedFileURL == production.anchor.standardizedFileURL
            ? production.directory.deletingLastPathComponent().appendingPathComponent("CredentialBroker")
            : context.anchor.appendingPathComponent("credentialBroker")
        return Context(anchor: context.anchor, directory: directory, appURL: app,
            bundledBrokerURL: app.appendingPathComponent("Contents/Helpers/StanMicCredentialBroker"), signingContext: context)
    }
    static func installAndPin(app: URL, context: LocalSigning.Context) throws {
        guard let config = try LocalSigning.loadConfiguration(context) else {
            throw Failure(message: "固定鑰匙圈輔助程式需要既有的本機固定簽章身分。")
        }
        try LocalSigning.verifyPinned(app, config: config, identifier: LocalSigning.appIdentifier)
        let client = installerContext(app: app, context: context)
        if try readPin(app, config: config) != nil {
            _ = try prepare(context: client)
            return
        }
        _ = try bootstrap(context: client, config: config) { pin in
            let destination = pinURL(app)
            try JSONEncoder().encode(pin).write(to: destination, options: .withoutOverwriting)
            do {
                try LocalSigning.signApp(app, config: config)
                _ = try trustedPin(client, config: config)
            } catch {
                try? FileManager.default.removeItem(at: destination)
                throw error
            }
        }
    }
    @discardableResult static func propagatePin(from installed: URL, to staged: URL,
                                                 config: LocalSigning.Configuration) throws -> Bool {
        try LocalSigning.verifyPinnedApp(installed, config: config)
        guard let pin = try readPin(installed, config: config) else { return false }
        let destination = pinURL(staged)
        var info = stat()
        if lstat(destination.path, &info) == 0 {
            try require(info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG), "更新內的固定鑰匙圈身分不是一般檔案。")
            try FileManager.default.removeItem(at: destination)
        } else { try require(errno == ENOENT, "無法準備更新內的固定鑰匙圈身分。") }
        try JSONEncoder().encode(pin).write(to: destination, options: .withoutOverwriting)
        return true
    }
    #if BROKER_TESTING
    @discardableResult static func bootstrapForTests(context: Context) throws -> URL {
        guard let config = try LocalSigning.loadConfiguration(context.signingContext) else {
            throw Failure(message: "Missing isolated signing identity")
        }
        return try bootstrap(context: context, config: config, commit: { _ in })
    }
    #endif
    private static func uniqueCode(_ code: SecStaticCode) throws -> Data {
        var info: CFDictionary?
        try LocalSigning.check(SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info), "Read broker identity")
        guard let fields = info as? [String: Any], let unique = fields[kSecCodeInfoUnique as String] as? Data,
              let flags = fields[kSecCodeInfoFlags as String] as? NSNumber, flags.uint32Value & 0x10000 != 0 else {
            throw Failure(message: "鑰匙圈輔助程式缺少 Hardened Runtime 保護。")
        }
        return unique
    }
    // Called only during trusted bootstrap (or fixture setup), never to derive
    // expected identity from the mutable helper immediately before launch.
    static func codeHashes(_ path: URL) throws -> [String] {
        // Validate every slice before enumeration. Some OS versions defer an
        // unavailable architecture error until the selected object is checked.
        try LocalSigning.checkCode(path)
        var hashes = Set<String>()
        for architecture in ["x86_64", "arm64"] {
            var result: SecStaticCode?
            let status = SecStaticCodeCreateWithPathAndAttributes(path as CFURL, [],
                [kSecCodeAttributeArchitecture as String: architecture] as CFDictionary, &result)
            // A thin build has only one of these architectures. Unsupported
            // slices are skipped; absence of every supported slice fails closed.
            if status != errSecSuccess { continue }
            guard let code = result else { throw Failure(message: "無法讀取固定輔助程式的架構。") }
            if SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), nil) != errSecSuccess { continue }
            hashes.insert(try uniqueCode(code).map { String(format: "%02x", $0) }.joined())
        }
        let values = hashes.sorted()
        try require(validCodeHashes(values), "固定輔助程式沒有可驗證的架構身分。")
        return values
    }
    private static func authenticateChild(_ process: Process, requirement: SecRequirement, codeHashes: [String]) throws {
        try require(process.isRunning, "鑰匙圈輔助程式未正常啟動。")
        var guest: SecCode?
        try LocalSigning.check(SecCodeCopyGuestWithAttributes(nil,
            [kSecGuestAttributePid as String: process.processIdentifier] as CFDictionary, [], &guest), "Identify broker process")
        guard let child = guest else { throw Failure(message: "無法識別鑰匙圈輔助程式。") }
        try LocalSigning.check(SecCodeCheckValidity(child, [], requirement), "Authenticate broker process")
        var staticChild: SecStaticCode?
        try LocalSigning.check(SecCodeCopyStaticCode(child, [], &staticChild), "Read launched broker code")
        guard let childCode = staticChild else { throw Failure(message: "無法識別鑰匙圈輔助程式程式碼。") }
        let actual = try uniqueCode(childCode).map { String(format: "%02x", $0) }.joined()
        try require(codeHashes.contains(actual) && process.isRunning, "鑰匙圈輔助程式身分與 App 內的固定身分不符。")
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
        guard let config = try LocalSigning.loadConfiguration(context.signingContext) else {
            throw Failure(message: "本機固定簽章設定已遺失。")
        }
        try LocalSigning.verifyPinned(context.appURL, config: config, identifier: LocalSigning.appIdentifier)
        let pin = try trustedPin(context, config: config)
        let hashes = pin.codeHashes.map { "cdhash H\"\($0)\"" }.joined(separator: " or ")
        // Enforce the sealed hashes in the dynamic validity check itself, not
        // only in a later inspection of the child's on-disk signature.
        let requirement = try LocalSigning.explicitRequirement(
            LocalSigning.requirement(identifier: identifier, fingerprint: pin.certificateSHA1) + " and (" + hashes + ")")
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
        try authenticateChild(process, requirement: requirement, codeHashes: pin.codeHashes)
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
