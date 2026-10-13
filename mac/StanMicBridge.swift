import AppKit
import AVFoundation
import Security
import CryptoKit
import Darwin

// macOS 12+, Swift 5. No audio files, transcripts, or credential-bearing logs.
// All lifecycle and socket state belongs to the main thread. The audio tap only
// converts a bounded buffer and deposits it in a small, synchronized mailbox.
private struct Connection: Codable {
    let origin: String
    let token: String

    static func parse(_ text: String) -> Connection? {
        guard let parts = URLComponents(string: text.trimmingCharacters(in: .whitespacesAndNewlines)),
              parts.scheme?.lowercased() == "https", let host = parts.host, !host.isEmpty,
              parts.user == nil, parts.password == nil,
              parts.path.isEmpty || parts.path == "/",
              let fragment = parts.fragment,
              let secret = URLComponents(string: "?" + fragment)?.queryItems?
                .first(where: { $0.name == "token" })?.value,
              !secret.isEmpty, secret.utf8.count <= 1024 else { return nil }
        var base = URLComponents()
        base.scheme = "https"
        base.host = host.lowercased()
        base.port = parts.port
        guard let origin = base.string else { return nil }
        return Connection(origin: origin, token: secret)
    }

    var socketRequest: URLRequest? {
        guard var parts = URLComponents(string: origin) else { return nil }
        parts.scheme = "wss"
        parts.path = "/ws"
        parts.queryItems = [URLQueryItem(name: "token", value: token)]
        guard let url = parts.url else { return nil }
        var request = URLRequest(url: url)
        request.setValue(origin, forHTTPHeaderField: "Origin")
        request.timeoutInterval = 10
        return request
    }
}

private enum Credentials {
    // Fixed-signing installations use a stable child identity. Ad-hoc users
    // retain the original Keychain path and its per-update approval behavior.
    static private(set) var lastError: String?
    static var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: "com.stan.micbridge",
         kSecAttrAccount as String: "receiver"]
    }

    static func load() -> Connection? {
        lastError = nil
        do {
            if try LocalSigning.isEnabled(for: Bundle.main.bundleURL) {
                guard let data = try CredentialBrokerClient.perform("load") else { return nil }
                return try JSONDecoder().decode(Connection.self, from: data)
            }
        } catch { lastError = error.localizedDescription; return nil }
        var search = query
        search[kSecReturnData as String] = true
        search[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(search as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return try? JSONDecoder().decode(Connection.self, from: data)
    }

    static func save(_ connection: Connection) -> Bool {
        lastError = nil
        guard let data = try? JSONEncoder().encode(connection) else { return false }
        do {
            if try LocalSigning.isEnabled(for: Bundle.main.bundleURL) {
                _ = try CredentialBrokerClient.perform("save", payload: data)
                return true
            }
        } catch { lastError = error.localizedDescription; return false }
        let attributes = [kSecValueData as String: data]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecSuccess { return true }
        guard status == errSecItemNotFound else { return false }
        var insert = query
        insert[kSecValueData as String] = data
        insert[kSecAttrLabel as String] = "Stan Mic Bridge receiver"
        return SecItemAdd(insert as CFDictionary, nil) == errSecSuccess
    }

    static func remove() -> Bool {
        lastError = nil
        do {
            if try LocalSigning.isEnabled(for: Bundle.main.bundleURL) {
                _ = try CredentialBrokerClient.perform("remove")
                return true
            }
        } catch { lastError = error.localizedDescription; return false }
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}

// Public release metadata is completely separate from the private audio connection.
private struct StableVersion: Comparable {
    let parts: [Int]
    init?(_ value: String) {
        let text = value.hasPrefix("v") ? String(value.dropFirst()) : value
        let fields = text.split(separator: ".", omittingEmptySubsequences: false)
        guard fields.count == 3 else { return nil }
        var numbers: [Int] = []
        for field in fields {
            guard !field.isEmpty, field.allSatisfy({ $0 >= "0" && $0 <= "9" }),
                  field.count == 1 || field.first != "0", let number = Int(field) else { return nil }
            numbers.append(number)
        }
        parts = numbers
    }
    static func < (lhs: Self, rhs: Self) -> Bool {
        lhs.parts.lexicographicallyPrecedes(rhs.parts)
    }
}

private struct PublicRelease: Decodable {
    struct Asset: Decodable {
        let name: String
        let browser_download_url: String
        let digest: String?
        let size: Int
    }
    let tag_name: String
    let html_url: String
    let body: String?
    let draft: Bool
    let prerelease: Bool
    var assets: [Asset]? = nil

    var installAsset: Asset? {
        guard trustedURL != nil else { return nil }
        let matches = (assets ?? []).filter { $0.name == "StanMicBridge-macOS.zip" }
        guard matches.count == 1, let asset = matches.first,
              asset.size > 0, asset.size <= 64 * 1024 * 1024,
              asset.browser_download_url == "https://github.com/stantheman0128/stan-mic-bridge/releases/download/" + tag_name + "/StanMicBridge-macOS.zip",
              let digest = asset.digest, digest.hasPrefix("sha256:"), digest.count == 71,
              digest.dropFirst(7).allSatisfy({ "0123456789abcdef".contains($0) }) else { return nil }
        return asset
    }

    var stableVersion: StableVersion? {
        guard !draft, !prerelease else { return nil }
        return StableVersion(tag_name)
    }
    var trustedURL: URL? {
        guard stableVersion != nil, let parts = URLComponents(string: html_url),
              parts.scheme == "https", parts.host == "github.com", parts.port == nil,
              parts.user == nil, parts.password == nil, parts.query == nil, parts.fragment == nil,
              parts.percentEncodedPath == "/stantheman0128/stan-mic-bridge/releases/tag/" + tag_name else { return nil }
        return parts.url
    }
}

private enum InstallFailure: Error { case invalid }

// This session never shares cookies, credentials, or the microphone URL.
private final class ReleaseDownload: NSObject, URLSessionDataDelegate {
    var completion: ((Result<Data, Error>) -> Void)?
    var progress: ((Int) -> Void)?
    private var bytes = Data()
    private let expectedSize: Int
    init(size: Int) { expectedSize = size }
    static func allowedRedirect(_ url: URL?) -> Bool {
        guard let url = url, let parts = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return false }
        return parts.scheme == "https" && parts.port == nil && parts.user == nil && parts.password == nil
            && ["github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"].contains(parts.host ?? "")
    }
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        guard Self.allowedRedirect(request.url), let url = request.url else { completionHandler(nil); return }
        completionHandler(URLRequest(url: url))
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard let response = response as? HTTPURLResponse, response.statusCode == 200,
              Self.allowedRedirect(response.url),
              response.expectedContentLength == -1 || response.expectedContentLength == Int64(expectedSize) else {
            completionHandler(.cancel); return
        }
        completionHandler(.allow)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard bytes.count + data.count <= expectedSize else { dataTask.cancel(); return }
        bytes.append(data)
        progress?(bytes.count * 100 / expectedSize)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error = error { completion?(.failure(error)) }
        else if bytes.count != expectedSize { completion?(.failure(InstallFailure.invalid)) }
        else { completion?(.success(bytes)) }
        completion = nil
        session.finishTasksAndInvalidate()
    }
}

private enum UpdatePaths {
    // Resolve only OS-provided anchors. Foundation's URL standardization may
    // rewrite /private/var back to /var, so keep the canonical POSIX spelling.
    static func canonicalAnchor(_ anchor: URL) -> String? {
        guard let pointer = realpath(anchor.path, nil) else { return nil }
        defer { free(pointer) }
        return String(cString: pointer)
    }
    static func matches(_ candidate: String, relative: String, anchor: URL) -> Bool {
        guard let canonical = canonicalAnchor(anchor) else { return false }
        let raw = anchor.path.hasSuffix("/") ? String(anchor.path.dropLast()) : anchor.path
        return candidate == raw + "/" + relative || candidate == canonical + "/" + relative
    }
    static func existing(_ relative: String, anchor: URL) -> URL? {
        let components = relative.split(separator: "/", omittingEmptySubsequences: false)
        guard !components.isEmpty, components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }),
              var path = canonicalAnchor(anchor) else { return nil }
        for component in components {
            path += "/" + component
            var info = stat()
            guard lstat(path, &info) == 0, info.st_mode & mode_t(S_IFMT) != mode_t(S_IFLNK) else { return nil }
        }
        return URL(fileURLWithPath: path)
    }
}

private enum UpdateResume {
    struct Intent: Codable { let parentPID: Int32; let build: String; let createdAt: Double }
    struct Grant: Codable { let build: String; let createdAt: Double; let nonce: String }
    static func requested(transmitting: Bool) -> Bool { transmitting }
    static func authorized(grant: Bool, credentials: Bool, permission: AVAuthorizationStatus, testMode: Bool) -> Bool {
        grant && credentials && permission == .authorized && !testMode
    }
    static func fresh(_ timestamp: Double, now: Double) -> Bool {
        timestamp.isFinite && timestamp <= now + 5 && now - timestamp <= 600
    }
    static func writeIntent(root: URL, build: String, parentPID: Int32) throws {
        let file = root.appendingPathComponent("resume-intent.json")
        let data = try JSONEncoder().encode(Intent(parentPID: parentPID, build: build, createdAt: Date().timeIntervalSince1970))
        try data.write(to: file, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
    }
    // Consume before sending readiness: the helper removes its staging directory
    // as soon as readiness is confirmed. A normal launch has no grant argument.
    static func consume(arguments: [String], build: String, now: Double = Date().timeIntervalSince1970) -> Bool {
        guard arguments.count == 5, ["--update-ready", "--test-update-resume"].contains(arguments[1]), arguments[3] == "--resume-update",
              arguments[4].count == 64, arguments[4].allSatisfy({ "0123456789abcdef".contains($0) }),
              let receipt = UpdateStaging.validReceipt(arguments: arguments) else { return false }
        let file = receipt.deletingLastPathComponent().appendingPathComponent("resume-once.json")
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: file.path),
              attributes[.type] as? FileAttributeType == .typeRegular,
              (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == geteuid(),
              (attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600,
              ((attributes[.size] as? NSNumber)?.intValue ?? 99999) <= 4096,
              let data = try? Data(contentsOf: file) else { return false }
        do { try FileManager.default.removeItem(at: file) } catch { return false }
        guard let grant = try? JSONDecoder().decode(Grant.self, from: data) else { return false }
        return grant.build == build && grant.nonce == arguments[4] && fresh(grant.createdAt, now: now)
    }
}

private enum UpdateStaging {
    static var isMenuTest: Bool {
        CommandLine.arguments.count == 2 && CommandLine.arguments[1] == "--test-update-menu"
    }
    static var isStartupTest: Bool {
        let arguments = CommandLine.arguments
        return isMenuTest || (arguments.count == 3 && arguments[1] == "--test-update-startup")
            || (arguments.count == 5 && arguments[1] == "--test-update-resume" && arguments[3] == "--resume-update")
    }
    static func receiptRootName(_ name: String) -> Bool {
        let prefix = "StanMicBridge-update-"
        return name.hasPrefix(prefix) && UUID(uuidString: String(name.dropFirst(prefix.count))) != nil
    }
    static func validReceipt(arguments: [String]) -> URL? {
        guard (arguments.count == 3 || (arguments.count == 5 && arguments[3] == "--resume-update")),
              arguments[1] == "--update-ready" || (arguments.count == 3 && arguments[1] == "--test-update-startup")
                || (arguments.count == 5 && arguments[1] == "--test-update-resume") else { return nil }
        let requested = URL(fileURLWithPath: arguments[2])
        let rootName = requested.deletingLastPathComponent().lastPathComponent
        let temporary = FileManager.default.temporaryDirectory
        guard requested.lastPathComponent == "update-ready.json", receiptRootName(rootName),
              UpdatePaths.matches(arguments[2], relative: rootName + "/update-ready.json", anchor: temporary),
              let root = UpdatePaths.existing(rootName, anchor: temporary),
              let attributes = try? FileManager.default.attributesOfItem(atPath: root.path),
              attributes[.type] as? FileAttributeType == .typeDirectory,
              (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == geteuid(),
              (attributes[.posixPermissions] as? NSNumber)?.intValue == 0o700 else { return nil }
        let receipt = root.appendingPathComponent("update-ready.json")
        var receiptInfo = stat()
        guard lstat(receipt.path, &receiptInfo) != 0, errno == ENOENT else { return nil }
        return receipt
    }
    static func acknowledgeStartup(resumeGranted: Bool) {
        guard let receipt = validReceipt(arguments: CommandLine.arguments),
              let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String,
              let data = try? JSONSerialization.data(withJSONObject: ["pid": ProcessInfo.processInfo.processIdentifier, "build": build,
                  "resumeGrantConsumed": resumeGranted] as [String: Any]) else { return }
        try? data.write(to: receipt, options: .atomic)
    }
    static func command(_ path: String, _ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        let timeout = DispatchWorkItem { if process.isRunning { process.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + 45, execute: timeout)
        defer { timeout.cancel() }
        var output = Data()
        while let data = try pipe.fileHandleForReading.read(upToCount: 65536), !data.isEmpty {
            output.append(data)
            if output.count > 2 * 1024 * 1024 { process.terminate(); throw InstallFailure.invalid }
        }
        process.waitUntilExit()
        guard process.terminationStatus == 0, let text = String(data: output, encoding: .utf8) else { throw InstallFailure.invalid }
        return text
    }
    static func safeEntry(_ name: String) -> Bool {
        guard name.hasPrefix("Stan Mic Bridge.app/"), !name.contains("\\"), !name.contains("\r"),
              !name.contains("\0") else { return false }
        return !name.split(separator: "/", omittingEmptySubsequences: false).contains(where: { $0 == ".." || $0 == "." })
    }
    static func prepare(_ data: Data, release: PublicRelease, root: URL) throws -> URL {
        guard let asset = release.installAsset,
              "sha256:" + SHA256.hash(data: data).map({ String(format: "%02x", $0) }).joined() == asset.digest else { throw InstallFailure.invalid }
        let archive = root.appendingPathComponent("update.zip")
        try data.write(to: archive, options: .atomic)
        let entries = try command("/usr/bin/unzip", ["-Z1", archive.path]).split(separator: "\n").map(String.init)
        guard !entries.isEmpty, entries.count < 10000, Set(entries).count == entries.count,
              entries.allSatisfy(safeEntry) else { throw InstallFailure.invalid }
        let details = try command("/usr/bin/zipinfo", ["-l", archive.path]).split(separator: "\n")
        var count = 0
        var total: Int64 = 0
        for line in details {
            let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            // zipinfo's Unix mode field must identify only regular files or directories.
            guard let mode = fields.first, mode.count == 10 else { continue }
            guard mode.first == "-" || mode.first == "d", fields.count >= 9,
                  let size = Int64(fields[3]), size >= 0, size <= 256 * 1024 * 1024 else { throw InstallFailure.invalid }
            count += 1
            total += size
            guard total <= 256 * 1024 * 1024 else { throw InstallFailure.invalid }
        }
        guard count == entries.count else { throw InstallFailure.invalid }
        let directory = root.appendingPathComponent("expanded", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        _ = try command("/usr/bin/ditto", ["-x", "-k", archive.path, directory.path])
        let app = directory.appendingPathComponent("Stan Mic Bridge.app", isDirectory: true)
        guard let bundle = Bundle(url: app), bundle.bundleIdentifier == "com.stan.micbridge",
              let version = bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String,
              StableVersion(version) == release.stableVersion else { throw InstallFailure.invalid }
        _ = try command("/usr/bin/codesign", ["--verify", "--deep", "--strict", app.path])
        return app
    }
}

private enum MicrophoneAuthorizationAction: Equatable {
    case connect, request, denied, restricted

    static func action(for status: AVAuthorizationStatus) -> Self {
        switch status {
        case .authorized: return .connect
        case .notDetermined: return .request
        case .denied: return .denied
        case .restricted: return .restricted
        @unknown default: return .restricted
        }
    }
}

private func testUpdatePolicy() {
    precondition(!UpdateResume.requested(transmitting: false)) // Stop during download.
    precondition(UpdateResume.requested(transmitting: true))
    precondition(UpdateResume.authorized(grant: true, credentials: true, permission: .authorized, testMode: false))
    precondition(!UpdateResume.authorized(grant: false, credentials: true, permission: .authorized, testMode: false))
    precondition(!UpdateResume.authorized(grant: true, credentials: false, permission: .authorized, testMode: false))
    precondition(!UpdateResume.authorized(grant: true, credentials: true, permission: .authorized, testMode: true))
    for permission in [AVAuthorizationStatus.notDetermined, .denied, .restricted] {
        precondition(!UpdateResume.authorized(grant: true, credentials: true, permission: permission, testMode: false))
    }
    do {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("StanMicBridge-update-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let grantFile = root.appendingPathComponent("resume-once.json")
        let nonce = String(repeating: "a", count: 64)
        let arguments = ["app", "--update-ready", root.appendingPathComponent("update-ready.json").path, "--resume-update", nonce]
        precondition(UpdatePaths.existing(root.lastPathComponent, anchor: FileManager.default.temporaryDirectory) != nil)
        precondition(UpdateStaging.validReceipt(arguments: arguments) != nil)
        if let canonical = UpdatePaths.canonicalAnchor(FileManager.default.temporaryDirectory) {
            var canonicalArguments = arguments
            canonicalArguments[2] = canonical + "/" + root.lastPathComponent + "/update-ready.json"
            precondition(UpdateStaging.validReceipt(arguments: canonicalArguments) != nil)
        } else { preconditionFailure("Cannot resolve the current user's temporary anchor") }
        let linkedRoot = FileManager.default.temporaryDirectory.appendingPathComponent("StanMicBridge-update-" + UUID().uuidString)
        try FileManager.default.createSymbolicLink(at: linkedRoot, withDestinationURL: root)
        defer { try? FileManager.default.removeItem(at: linkedRoot) }
        var linkedArguments = arguments
        linkedArguments[2] = linkedRoot.appendingPathComponent("update-ready.json").path
        precondition(UpdateStaging.validReceipt(arguments: linkedArguments) == nil)
        precondition(UpdatePaths.existing(linkedRoot.lastPathComponent, anchor: FileManager.default.temporaryDirectory) == nil)
        precondition(UpdatePaths.existing("../" + root.lastPathComponent, anchor: FileManager.default.temporaryDirectory) == nil)
        func seed(build: String = "6", timestamp: Double = 1000) throws {
            try JSONEncoder().encode(UpdateResume.Grant(build: build, createdAt: timestamp, nonce: nonce)).write(to: grantFile)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: grantFile.path)
        }
        try seed()
        precondition(!UpdateResume.consume(arguments: ["app"], build: "6", now: 1000))
        precondition(!UpdateResume.consume(arguments: Array(arguments.prefix(3)), build: "6", now: 1000)) // Old helper.
        precondition(UpdateResume.consume(arguments: arguments, build: "6", now: 1000))
        precondition(!UpdateResume.consume(arguments: arguments, build: "6", now: 1000)) // One shot.
        try seed(build: "5")
        precondition(!UpdateResume.consume(arguments: arguments, build: "6", now: 1000))
        precondition(!FileManager.default.fileExists(atPath: grantFile.path))
        try seed(timestamp: 399)
        precondition(!UpdateResume.consume(arguments: arguments, build: "6", now: 1000))
        try seed(timestamp: 1006)
        precondition(!UpdateResume.consume(arguments: arguments, build: "6", now: 1000))
        try seed()
        var wrongNonce = arguments
        wrongNonce[4] = String(repeating: "b", count: 64)
        precondition(!UpdateResume.consume(arguments: wrongNonce, build: "6", now: 1000))
    } catch { preconditionFailure("Update resume file-boundary tests failed: \(error)") }
    // Granted access never enters the permission-request path; a refusal never
    // triggers another request. Only macOS's undetermined state may prompt.
    precondition(MicrophoneAuthorizationAction.action(for: .authorized) == .connect)
    precondition(MicrophoneAuthorizationAction.action(for: .notDetermined) == .request)
    precondition(MicrophoneAuthorizationAction.action(for: .denied) == .denied)
    precondition(MicrophoneAuthorizationAction.action(for: .restricted) == .restricted)
    precondition(StableVersion("1.9.0")! < StableVersion("1.10.0")!)
    precondition(StableVersion("v1.1.0")! == StableVersion("1.1.0")!)
    precondition(StableVersion("2.0.0")! > StableVersion("1.99.99")!)
    for bad in ["1.0", "01.0.0", "1.0.0-beta", "1.0.0+dev", "1.-1.0", "1.0.0/"] {
        precondition(StableVersion(bad) == nil)
    }
    let canonical = "https://github.com/stantheman0128/stan-mic-bridge/releases/tag/v1.1.0"
    func release(_ url: String, draft: Bool = false, prerelease: Bool = false) -> PublicRelease {
        PublicRelease(tag_name: "v1.1.0", html_url: url, body: nil, draft: draft, prerelease: prerelease)
    }
    precondition(release(canonical).trustedURL != nil)
    precondition(release(canonical, draft: true).trustedURL == nil)
    precondition(release(canonical, prerelease: true).trustedURL == nil)
    for bad in [canonical + "?x=1", canonical + "#x", canonical + "/extra",
                canonical.replacingOccurrences(of: "https:", with: "http:"),
                canonical.replacingOccurrences(of: "github.com", with: "github.com.evil.test"),
                canonical.replacingOccurrences(of: "stantheman0128", with: "someone"),
                canonical.replacingOccurrences(of: "v1.1.0", with: "v2.0.0")] {
        precondition(release(bad).trustedURL == nil)
    }
    let downloadURL = "https://github.com/stantheman0128/stan-mic-bridge/releases/download/v1.1.0/StanMicBridge-macOS.zip"
    func candidate(_ url: String? = nil, digest: String? = "sha256:" + String(repeating: "a", count: 64), size: Int = 1024) -> PublicRelease {
        var value = release(canonical)
        value.assets = [.init(name: "StanMicBridge-macOS.zip", browser_download_url: url ?? downloadURL, digest: digest, size: size)]
        return value
    }
    precondition(candidate().installAsset != nil)
    precondition(release(canonical).installAsset == nil)
    precondition(candidate(digest: nil).installAsset == nil)
    precondition(candidate(digest: "sha256:" + String(repeating: "g", count: 64)).installAsset == nil)
    precondition(candidate(size: 0).installAsset == nil)
    precondition(candidate(size: 64 * 1024 * 1024 + 1).installAsset == nil)
    for bad in [downloadURL + "?x=1", downloadURL.replacingOccurrences(of: "v1.1.0", with: "v2.0.0"),
                downloadURL.replacingOccurrences(of: "github.com", with: "evil.test")] {
        precondition(candidate(bad).installAsset == nil)
    }
    for bad in ["http://github.com/a", "https://github.com.evil.test/a", "https://user@github.com/a", "https://github.com:443/a"] {
        precondition(!ReleaseDownload.allowedRedirect(URL(string: bad)))
    }
    precondition(ReleaseDownload.allowedRedirect(URL(string: "https://release-assets.githubusercontent.com/a?signature=test")))
    precondition(UpdateStaging.safeEntry("Stan Mic Bridge.app/Contents/MacOS/StanMicBridge"))
    precondition(UpdateStaging.receiptRootName("StanMicBridge-update-" + UUID().uuidString))
    precondition(!UpdateStaging.receiptRootName("StanMicBridge-update-../../other"))
    precondition(!UpdateStaging.receiptRootName("Other-" + UUID().uuidString))
    for bad in ["../Stan Mic Bridge.app/x", "/Stan Mic Bridge.app/x", "Stan Mic Bridge.app/../x", "Stan Mic Bridge.app/a\\b", "Other.app/x"] {
        precondition(!UpdateStaging.safeEntry(bad))
    }
    // A five-chunk burst exceeds the existing 100 ms mailbox bound: account
    // for the dropped oldest chunk separately from subsequent expiry.
    let box = AudioMailbox(sourceRate: 48000, startedAt: 0)
    box.recordCaptured(5120)
    box.recordConverted(5120)
    for _ in 0..<5 { box.put(Data(count: 1024 * MemoryLayout<Float>.size), now: 1) }
    precondition(box.snapshot(now: 1).overflowFrames == 1024)
    precondition(box.take(now: 1.2) == nil)
    let audio = box.snapshot(now: 1.2)
    precondition(audio.expiredFrames == 4096 && audio.sentFrames == 0)
    precondition(audio.capturedFrames == 5120 && audio.convertedFrames == 5120 && audio.maximumTapFrames == 5120)
    box.put(Data(count: 480 * MemoryLayout<Float>.size), now: 2)
    precondition(box.take(now: 2)?.bytes.count == 1920)
    box.recordSent(480)
    precondition(box.snapshot(now: 2).sentFrames == 480)
    print("Update, microphone authorization, and audio accounting checks passed")
}

private final class AudioMailbox {
    struct Snapshot {
        let sourceRate: Double
        let elapsed: Double
        let maximumTapFrames: Int
        let capturedFrames: Int64
        let convertedFrames: Int64
        let sentFrames: Int64
        let overflowFrames: Int64
        let expiredFrames: Int64
    }
    struct Packet {
        let bytes: Data
        let captured: TimeInterval
    }
    private let lock = NSLock()
    private var packets: [Packet] = []
    private var byteCount = 0
    private var fault = false
    private let sourceRate: Double
    private let startedAt: Double
    private var maximumTapFrames = 0
    private var capturedFrames: Int64 = 0
    private var convertedFrames: Int64 = 0
    private var sentFrames: Int64 = 0
    private var overflowFrames: Int64 = 0
    private var expiredFrames: Int64 = 0

    init(sourceRate: Double, startedAt: Double = ProcessInfo.processInfo.systemUptime) {
        self.sourceRate = sourceRate
        self.startedAt = startedAt
    }
    func recordCaptured(_ frames: Int) {
        lock.lock(); defer { lock.unlock() }
        capturedFrames += Int64(frames)
        maximumTapFrames = max(maximumTapFrames, frames)
    }
    func recordConverted(_ frames: Int) { lock.lock(); convertedFrames += Int64(frames); lock.unlock() }
    func recordSent(_ frames: Int) { lock.lock(); sentFrames += Int64(frames); lock.unlock() }
    func snapshot(now: Double = ProcessInfo.processInfo.systemUptime) -> Snapshot {
        lock.lock(); defer { lock.unlock() }
        return Snapshot(sourceRate: sourceRate, elapsed: max(0, now - startedAt), maximumTapFrames: maximumTapFrames,
                        capturedFrames: capturedFrames, convertedFrames: convertedFrames, sentFrames: sentFrames,
                        overflowFrames: overflowFrames, expiredFrames: expiredFrames)
    }

    func put(_ data: Data, now: Double = ProcessInfo.processInfo.systemUptime) {
        lock.lock()
        defer { lock.unlock() }
        // 100 ms of 48 kHz float32 audio. Drop oldest audio on congestion.
        guard !data.isEmpty, data.count <= 19200 else { fault = true; return }
        while !packets.isEmpty && (byteCount + data.count > 19200 || packets.count >= 8) {
            let dropped = packets.removeFirst().bytes.count
            byteCount -= dropped
            overflowFrames += Int64(dropped / MemoryLayout<Float>.size)
        }
        packets.append(Packet(bytes: data, captured: now))
        byteCount += data.count
    }

    func take(now: Double = ProcessInfo.processInfo.systemUptime) -> Packet? {
        lock.lock()
        defer { lock.unlock() }
        while !packets.isEmpty {
            let packet = packets.removeFirst()
            byteCount -= packet.bytes.count
            if now - packet.captured < 0.15 { return packet }
            expiredFrames += Int64(packet.bytes.count / MemoryLayout<Float>.size)
        }
        return nil
    }

    func fail() { lock.lock(); fault = true; lock.unlock() }
    func failed() -> Bool { lock.lock(); defer { lock.unlock() }; return fault }
}

// Forbid redirects rather than forwarding the token or Origin to another host.
private final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private var statusItem: NSStatusItem!
    private let stateItem = NSMenuItem(title: "已停止", action: nil, keyEquivalent: "")
    private let startItem = NSMenuItem(title: "開始傳送", action: #selector(start), keyEquivalent: "")
    private let stopItem = NSMenuItem(title: "停止傳送", action: #selector(stop), keyEquivalent: "")
    private let audioStatusItem = NSMenuItem(title: "音訊狀態…", action: #selector(showAudioStatus), keyEquivalent: "")
    private let configureItem = NSMenuItem(title: "設定連線…", action: #selector(configure), keyEquivalent: "")
    private let forgetItem = NSMenuItem(title: "清除已儲存的連線…", action: #selector(forget), keyEquivalent: "")
    private let updateItem = NSMenuItem(title: "檢查更新…", action: #selector(checkUpdates), keyEquivalent: "")
    private let versionItem = NSMenuItem(title: "", action: nil, keyEquivalent: "")
    private let signingStatusItem = NSMenuItem(title: "簽署：正在確認…", action: nil, keyEquivalent: "")
    private let updateStatusItem = NSMenuItem(title: "尚未檢查更新", action: nil, keyEquivalent: "")
    private let installUpdateItem = NSMenuItem(title: "下載並安裝更新", action: #selector(installUpdate), keyEquivalent: "")
    private let releaseHistoryItem = NSMenuItem(title: "查看版本紀錄…", action: #selector(openReleaseHistory), keyEquivalent: "")
    private var updateSession: URLSession?
    private var updatePanel: NSPanel?
    private var statusMenuVisible = false
    private var statusMenuOpenCount = 0
    private var menuRevealPending = false
    private var offeredRelease: PublicRelease?
    private var installingUpdate = false
    private var installerHandoff = false
    private var stagingRoot: URL?
    private var connection: Connection?
    private var enabled = false
    private var sleeping = false
    private var generation = 0
    private var failures = 0
    private var socket: URLSessionWebSocketTask?
    private var session: URLSession?
    private var engine: AVAudioEngine?
    private var mailbox: AudioMailbox?
    private var lastAudioSnapshot: AudioMailbox.Snapshot?
    private var audioStatusPanel: NSPanel?
    private var engineObserver: NSObjectProtocol?
    private var workspaceObservers: [NSObjectProtocol] = []
    private var timer: Timer?
    private var retry: DispatchWorkItem?
    private var ready = false
    private var inFlight = false
    private var sendBegan: TimeInterval = 0
    private var connectedAt: TimeInterval = 0
    private var lastSent: TimeInterval = 0
    private var activity: NSObjectProtocol?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        let menu = NSMenu()
        menu.delegate = self
        menu.autoenablesItems = false
        menu.addItem(stateItem)
        menu.addItem(.separator())
        for item in [startItem, stopItem, configureItem, forgetItem] {
            item.target = self
            menu.addItem(item)
        }
        audioStatusItem.target = self
        menu.addItem(audioStatusItem)
        menu.addItem(.separator())
        versionItem.title = "目前版本：" + (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "未知")
        versionItem.isEnabled = false
        signingStatusItem.isEnabled = false
        updateStatusItem.isEnabled = false
        menu.addItem(versionItem)
        menu.addItem(signingStatusItem)
        menu.addItem(updateStatusItem)
        updateItem.target = self
        menu.addItem(updateItem)
        installUpdateItem.target = self
        installUpdateItem.isHidden = true
        installUpdateItem.toolTip = "下載完成後會安裝並重新開啟。安裝前仍在傳送且授權有效時會自動恢復；下載時按停止即可取消恢復。"
        menu.addItem(installUpdateItem)
        releaseHistoryItem.target = self
        menu.addItem(releaseHistoryItem)
        menu.addItem(.separator())
        let quit = NSMenuItem(title: "結束 Stan Mic Bridge", action: #selector(quitApp), keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)
        statusItem.menu = menu
        if !UpdateStaging.isMenuTest { refreshSigningStatus() }
        if let image = NSImage(systemSymbolName: "mic.fill", accessibilityDescription: "Stan Mic Bridge") {
            image.isTemplate = true
            statusItem.button?.image = image
            statusItem.button?.imagePosition = .imageLeading
        }
        let resumeGranted = UpdateResume.consume(arguments: CommandLine.arguments,
            build: Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "")
        // Consume the one-shot grant before readiness lets the helper clean up.
        UpdateStaging.acknowledgeStartup(resumeGranted: resumeGranted)
        let startupGeneration = generation
        // The explicit UI smoke-test mode exercises the real menu and receipt
        // without requiring a CI login Keychain or blocking on onboarding.
        connection = UpdateStaging.isStartupTest ? nil : Credentials.load()
        show(connection == nil ? "請先設定連線" : "已停止")
        if let failure = Credentials.lastError, !UpdateStaging.isStartupTest {
            show("鑰匙圈尚未就緒；連線已停止")
            DispatchQueue.main.async { [weak self] in self?.message("無法讀取已儲存連線", failure) }
        }
        if resumeGranted {
            let permission = AVCaptureDevice.authorizationStatus(for: .audio)
            if generation == startupGeneration && UpdateResume.authorized(grant: true,
                                       credentials: connection != nil, permission: permission, testMode: UpdateStaging.isStartupTest) {
                enabled = true
                failures = 0
                connect()
            } else if connection == nil {
                show("更新完成；請先設定連線，再手動開始")
            } else if permission != .authorized {
                show("更新完成；請手動開始並確認麥克風權限")
            }
        }
        let center = NSWorkspace.shared.notificationCenter
        workspaceObservers.append(center.addObserver(forName: NSWorkspace.willSleepNotification,
                                                     object: nil, queue: .main) { [weak self] _ in
            guard let self = self else { return }
            self.sleeping = true
            self.disconnect()
            if self.enabled { self.show("睡眠中，喚醒後重連") }
        })
        workspaceObservers.append(center.addObserver(forName: NSWorkspace.didWakeNotification,
                                                     object: nil, queue: .main) { [weak self] _ in
            guard let self = self else { return }
            self.sleeping = false
            if self.enabled { self.scheduleRetry(message: "已喚醒，準備重連") }
        })
        if connection == nil && !UpdateStaging.isStartupTest && !resumeGranted { DispatchQueue.main.async { self.configure() } }
        if UpdateStaging.isMenuTest { runUpdateMenuSmoke() }
    }

    private func show(_ text: String) {
        stateItem.title = text
        stateItem.isEnabled = false
        statusItem.button?.title = ready ? "Mic ●" : (enabled ? "Mic …" : "Mic ○")
        statusItem.button?.toolTip = "Stan Mic Bridge — " + text + "\n" + versionItem.title
        statusItem.button?.setAccessibilityLabel("Stan Mic Bridge — " + text)
        startItem.isEnabled = !enabled && connection != nil
        stopItem.isEnabled = enabled
        configureItem.isEnabled = !enabled
        forgetItem.isEnabled = !enabled && connection != nil
    }

    @objc private func checkUpdates() {
        guard updateSession == nil, !installingUpdate else { return }
        // Dismiss any previous error; the menu is the sole progress surface.
        updatePanel?.close()
        updateItem.isEnabled = false
        offeredRelease = nil
        installUpdateItem.isHidden = true
        setUpdateStatus("正在檢查更新…")
        revealUpdateMenu()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 15
        configuration.timeoutIntervalForResource = 20
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCredentialStorage = nil
        configuration.urlCache = nil
        let client = URLSession(configuration: configuration, delegate: NoRedirectDelegate(), delegateQueue: nil)
        updateSession = client
        var request = URLRequest(url: URL(string: "https://api.github.com/repos/stantheman0128/stan-mic-bridge/releases/latest")!)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")
        request.setValue("Stan-Mic-Bridge-Update-Check", forHTTPHeaderField: "User-Agent")
        client.dataTask(with: request) { [weak self] data, response, error in
            DispatchQueue.main.async {
                guard let self = self else { client.finishTasksAndInvalidate(); return }
                self.updateSession = nil
                client.finishTasksAndInvalidate()
                self.updateItem.isEnabled = true
                defer { self.revealUpdateMenu() }
                if error != nil {
                    self.setUpdateStatus("檢查失敗：網路無法使用，請重試")
                    return
                }
                guard let response = response as? HTTPURLResponse else {
                    self.setUpdateStatus("檢查失敗：無法辨識回應")
                    return
                }
                if response.statusCode == 404 {
                    self.setUpdateStatus("目前尚無正式發布版本")
                    return
                }
                if response.statusCode == 403 || response.statusCode == 429 {
                    self.setUpdateStatus("GitHub 暫時限制請求，請稍後重試")
                    return
                }
                guard response.statusCode == 200, let data = data, data.count <= 1048576,
                      let release = try? JSONDecoder().decode(PublicRelease.self, from: data) else {
                    self.setUpdateStatus("檢查失敗：發布資料不完整")
                    return
                }
                guard let latest = release.stableVersion, release.trustedURL != nil else {
                    self.setUpdateStatus("沒有可驗證的正式更新")
                    return
                }
                let currentText = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "未知"
                guard let current = StableVersion(currentText) else {
                    self.setUpdateStatus("無法判斷目前版本，請查看版本紀錄")
                    return
                }
                guard latest > current else {
                    self.setUpdateStatus("已是最新版本（\(currentText)）")
                    return
                }
                guard release.installAsset != nil else {
                    self.setUpdateStatus("\(release.tag_name) 安裝包尚未準備完成")
                    return
                }
                self.offeredRelease = release
                self.installUpdateItem.title = "下載並安裝 \(release.tag_name)"
                self.installUpdateItem.isEnabled = true
                self.installUpdateItem.isHidden = false
                self.setUpdateStatus("有更新可用：\(release.tag_name)")
            }
        }.resume()
    }

    // Error explanations remain modeless so an active audio session keeps running.
    private func showUpdate(_ title: String, _ detail: String) {
        updatePanel?.close()
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 540, height: 390),
                            styleMask: [.titled, .closable], backing: .buffered, defer: false)
        panel.title = title
        panel.isReleasedWhenClosed = false
        let scroll = NSScrollView(frame: NSRect(x: 20, y: 65, width: 500, height: 305))
        scroll.hasVerticalScroller = true
        let text = NSTextView(frame: NSRect(x: 0, y: 0, width: 480, height: 305))
        text.isEditable = false
        text.isSelectable = true
        text.font = NSFont.systemFont(ofSize: 13)
        text.string = detail
        text.isVerticallyResizable = true
        text.isHorizontallyResizable = false
        text.textContainer?.widthTracksTextView = true
        scroll.documentView = text
        panel.contentView?.addSubview(scroll)
        let close = NSButton(title: "關閉", target: self, action: #selector(closeUpdatePanel))
        close.frame = NSRect(x: 430, y: 20, width: 90, height: 30)
        close.bezelStyle = .rounded
        panel.contentView?.addSubview(close)
        updatePanel = panel
        panel.center()
        NSApp.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
    }

    @objc private func closeUpdatePanel() { updatePanel?.close() }
    @objc private func showAudioStatus() {
        let snapshot = mailbox?.snapshot() ?? lastAudioSnapshot
        let text: String
        if let value = snapshot {
            text = "\(mailbox == nil ? "最近一次音訊連線（已停止）" : "目前音訊連線")\n"
                + "經過時間：\(String(format: "%.2f", value.elapsed)) 秒\n"
                + "來源取樣率：\(Int(value.sourceRate)) Hz\n輸出取樣率：48000 Hz\n"
                + "最大單次收音：\(value.maximumTapFrames) frames\n"
                + "來源已擷取：\(value.capturedFrames) frames\n"
                + "已轉換（48 kHz）：\(value.convertedFrames) frames\n"
                + "WebSocket 傳送完成：\(value.sentFrames) frames\n"
                + "佇列滿而略過：\(value.overflowFrames) frames\n"
                + "佇列過期而略過：\(value.expiredFrames) frames\n\n"
                + "每次音訊重新連線會重新計數。此為按下按鈕時的快照，請按重新整理取得新值。傳送完成不代表接收端已播放。只保留記憶體中的數字，不錄音、不保存連線碼。"
        } else { text = "尚無音訊傳送資料。開始傳送後，再按重新整理即可查看。這裡只顯示計數，不會啟動麥克風。" }
        audioStatusPanel?.close()
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 510, height: 400),
                            styleMask: [.titled, .closable], backing: .buffered, defer: false)
        panel.title = "音訊狀態"
        panel.isReleasedWhenClosed = false
        let label = NSTextField(wrappingLabelWithString: text)
        label.frame = NSRect(x: 20, y: 65, width: 470, height: 315)
        label.isSelectable = true
        panel.contentView?.addSubview(label)
        let refresh = NSButton(title: "重新整理", target: self, action: #selector(showAudioStatus))
        refresh.frame = NSRect(x: 20, y: 20, width: 110, height: 30)
        refresh.bezelStyle = .rounded
        panel.contentView?.addSubview(refresh)
        audioStatusPanel = panel
        panel.center()
        NSApp.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
    }
    private func refreshSigningStatus() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let text: String
            do {
                text = try LocalSigning.isEnabled(for: Bundle.main.bundleURL)
                    ? "簽署：已啟用固定本機身分" : "簽署：尚未啟用固定本機身分"
            } catch {
                text = "簽署：需要修復（更新會停止）"
            }
            DispatchQueue.main.async { self?.signingStatusItem.title = text }
        }
    }
    private func setUpdateStatus(_ text: String) {
        updateStatusItem.title = text
    }
    func menuWillOpen(_ menu: NSMenu) {
        statusMenuVisible = true
        statusMenuOpenCount += 1
    }
    func menuDidClose(_ menu: NSMenu) { statusMenuVisible = false }
    private func revealUpdateMenu() {
        guard !menuRevealPending,
              !UpdateStaging.isStartupTest || UpdateStaging.isMenuTest else { return }
        menuRevealPending = true
        // Enter menu tracking from a run-loop timer, never a main GCD block:
        // synchronous tracking must leave that queue free for network/audio callbacks.
        let reveal = Timer(timeInterval: 0.01, repeats: false) { [weak self] _ in
            guard let self = self else { return }
            self.menuRevealPending = false
            if !self.statusMenuVisible { self.statusItem.button?.performClick(nil) }
        }
        RunLoop.main.add(reveal, forMode: .common)
    }
    private func runUpdateMenuSmoke() {
        // Real status-menu tracking, not a simulated state machine. The timeout
        // is a common-mode timer so it can fail even if the main queue stalls.
        let timeout = Timer(timeInterval: 5, repeats: false) { _ in
            fputs("Update menu smoke timed out while tracking\n", stderr)
            exit(1)
        }
        RunLoop.main.add(timeout, forMode: .common)
        setUpdateStatus("正在檢查更新…")
        updateItem.isEnabled = false
        revealUpdateMenu()
        let completion = Timer(timeInterval: 0.2, repeats: false) { [weak self] _ in
            DispatchQueue.main.async {
                guard let self = self, self.statusMenuVisible, self.statusMenuOpenCount == 1 else {
                    fputs("Update menu did not open through the production reveal path\n", stderr)
                    exit(1)
                }
                self.updateItem.isEnabled = true
                self.setUpdateStatus("已是最新版本（UI 測試）")
                self.revealUpdateMenu()
                // Give the production reveal callback a turn while menu tracking
                // continues: it must not click the already-open menu closed.
                let validate = Timer(timeInterval: 0.03, repeats: false) { _ in
                    guard self.statusMenuVisible, self.statusMenuOpenCount == 1,
                          self.updateStatusItem.title == "已是最新版本（UI 測試）",
                          self.updateItem.title == "檢查更新…", self.updateItem.isEnabled,
                          self.updatePanel == nil, self.audioStatusPanel == nil,
                          NSApp.modalWindow == nil, self.engine == nil, self.updateSession == nil else {
                        fputs("Update result was not visible during single-menu tracking\n", stderr)
                        exit(1)
                    }
                    self.statusItem.menu?.cancelTracking()
                    // AppKit may finish its dismissal animation after cancelTracking
                    // returns. Wait for menuDidClose, with a bounded common-mode poll.
                    let closeDeadline = ProcessInfo.processInfo.systemUptime + 2
                    let closed = Timer(timeInterval: 0.05, repeats: true) { timer in
                        if self.statusMenuVisible {
                            guard ProcessInfo.processInfo.systemUptime >= closeDeadline else { return }
                            timer.invalidate()
                            fputs("Update menu tracking did not close\n", stderr)
                            exit(1)
                        }
                        timer.invalidate()
                        timeout.invalidate()
                        print("Real update menu opened once, displayed async result while tracking, and closed; no audio or network used.")
                        exit(0)
                    }
                    RunLoop.main.add(closed, forMode: .common)
                }
                RunLoop.main.add(validate, forMode: .common)
            }
        }
        RunLoop.main.add(completion, forMode: .common)
    }
    @objc private func openReleaseHistory() {
        let url = URL(string: "https://github.com/stantheman0128/stan-mic-bridge/releases")!
        if !NSWorkspace.shared.open(url) { setUpdateStatus("無法開啟版本紀錄，請重試") }
    }
    @objc private func installUpdate() {
        guard !installingUpdate, updateSession == nil, let release = offeredRelease,
              let asset = release.installAsset, let url = URL(string: asset.browser_download_url) else { return }
        let home = FileManager.default.homeDirectoryForCurrentUser
        let relativeApp = "Applications/Stan Mic Bridge.app"
        guard UpdatePaths.matches(Bundle.main.bundleURL.path, relative: relativeApp, anchor: home),
              let destination = UpdatePaths.existing(relativeApp, anchor: home) else {
            showUpdate("請先安裝 App", "請將 Stan Mic Bridge.app 放到個人 Applications 資料夾後重新開啟，再使用 App 內更新。")
            return
        }
        let helper = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/StanMicUpdater")
        guard FileManager.default.isExecutableFile(atPath: helper.path) else {
            showUpdate("此安裝缺少更新元件", "請從正式發布頁下載完整 App，使用 Finder 安裝一次後即可使用 App 內更新。")
            return
        }
        installingUpdate = true
        updateItem.isEnabled = false
        installUpdateItem.isEnabled = false
        setUpdateStatus("正在下載更新…")
        updatePanel?.close()
        revealUpdateMenu()
        let downloader = ReleaseDownload(size: asset.size)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCredentialStorage = nil
        configuration.urlCache = nil
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 300
        let client = URLSession(configuration: configuration, delegate: downloader, delegateQueue: nil)
        updateSession = client
        downloader.progress = { [weak self] percent in
            DispatchQueue.main.async {
                self?.setUpdateStatus("正在下載更新 \(percent)%…")
            }
        }
        downloader.completion = { [weak self] result in
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.updateSession = nil
                guard case .success(let data) = result else { self.updateFailed(); return }
                self.setUpdateStatus("正在驗證更新…")
                guard let temporary = UpdatePaths.canonicalAnchor(FileManager.default.temporaryDirectory) else { self.updateFailed(); return }
                let root = URL(fileURLWithPath: temporary).appendingPathComponent("StanMicBridge-update-" + UUID().uuidString, isDirectory: true)
                do { try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]) }
                catch { self.updateFailed(); return }
                self.stagingRoot = root
                DispatchQueue.global(qos: .utility).async {
                    guard let staged = try? UpdateStaging.prepare(data, release: release, root: root) else {
                        DispatchQueue.main.async { self.updateFailed() }
                        return
                    }
                    do {
                        // The public digest and signature were verified above.
                        // Preserve the configured local identity before stopping audio.
                        try LocalSigning.prepareDownloadedApp(at: staged, installedApp: Bundle.main.bundleURL)
                    } catch {
                        DispatchQueue.main.async {
                            self.updateFailed(detail: "固定本機簽署未完成。若剛才取消授權或鑰匙圈仍鎖定，請解鎖登入鑰匙圈後重試。若原本的簽署憑證、私密金鑰或固定簽署設定已遺失，需先還原原始資料；重新執行安裝不會自動更換簽署身分。無法還原時，需要另行處理身分重設，macOS 可能要求重新授權。原本的 App 與連線設定未變更，麥克風可繼續使用。")
                        }
                        return
                    }
                    DispatchQueue.main.async {
                        let process = Process()
                        process.executableURL = helper
                        process.arguments = [String(ProcessInfo.processInfo.processIdentifier), staged.path, destination.path]
                        // Decide only now, after download/validation; an intervening
                        // Stop must never be replaced by an earlier snapshot.
                        if UpdateResume.requested(transmitting: self.enabled && self.ready),
                           let build = Bundle(url: staged)?.object(forInfoDictionaryKey: "CFBundleVersion") as? String {
                            do { try UpdateResume.writeIntent(root: root, build: build, parentPID: ProcessInfo.processInfo.processIdentifier) }
                            catch { self.updateFailed(); return }
                        }
                        do { try process.run() }
                        catch { self.updateFailed(); return }
                        self.installerHandoff = true
                        self.stop()
                        NSApp.terminate(nil)
                    }
                }
            }
        }
        client.dataTask(with: url).resume()
    }

    private func updateFailed(detail: String? = nil) {
        if let root = stagingRoot { try? FileManager.default.removeItem(at: root) }
        stagingRoot = nil
        installingUpdate = false
        updateItem.isEnabled = true
        installUpdateItem.isEnabled = offeredRelease != nil
        setUpdateStatus("更新未完成，可重試或重新檢查")
        showUpdate("更新未完成", detail ?? "無法下載、驗證或準備更新。原本的 App 與連線設定沒有變更，麥克風可繼續使用。請稍後重新檢查更新。")
    }

    @objc private func configure() {
        guard !enabled else { return }
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "設定 Windows 麥克風接收端"
        alert.informativeText = "貼上原本的完整 HTTPS 連結（包含 #token=…）。連線資訊會儲存在此 Mac 的鑰匙圈。儲存後，從選單按「開始傳送」。"
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 430, height: 26))
        field.placeholderString = "https://你的接收端:8443/#token=…"
        alert.accessoryView = field
        alert.addButton(withTitle: "儲存")
        alert.addButton(withTitle: "取消")
        alert.window.initialFirstResponder = field
        guard alert.runModal() == .alertFirstButtonReturn else { field.stringValue = ""; return }
        let parsed = Connection.parse(field.stringValue)
        field.stringValue = ""
        guard let candidate = parsed else {
            message("連結格式不正確", "請貼上 HTTPS 首頁連結，包含 #token= 後的完整連線碼。")
            return
        }
        guard Credentials.save(candidate) else {
            message("無法儲存鑰匙圈", Credentials.lastError ?? "請確認登入鑰匙圈已解鎖，再重新設定。")
            return
        }
        connection = candidate
        show("連線已儲存，尚未開始傳送")
    }

    @objc private func forget() {
        guard !enabled else { return }
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "清除這台 Mac 儲存的連線？"
        alert.informativeText = "只會清除此程式儲存的連線資料，Windows 接收端不會改變。"
        alert.addButton(withTitle: "清除")
        alert.addButton(withTitle: "取消")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        guard Credentials.remove() else {
            connection = nil
            show("連線已停止；請完成清除或重新設定")
            message("無法完成清除鑰匙圈", Credentials.lastError ?? "請確認登入鑰匙圈已解鎖後重試。")
            return
        }
        connection = nil
        show("請先設定連線")
    }

    private func message(_ title: String, _ detail: String) {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = detail
        alert.runModal()
    }

    @objc private func start() {
        guard !enabled, connection != nil else { return }
        enabled = true
        failures = 0
        switch MicrophoneAuthorizationAction.action(for: AVCaptureDevice.authorizationStatus(for: .audio)) {
        case .connect:
            connect()
        case .request:
            requestMicrophoneAccess()
        case .denied:
            microphoneUnavailable(restricted: false)
        case .restricted:
            microphoneUnavailable(restricted: true)
        }
    }

    private func microphoneUnavailable(restricted: Bool) {
        stop()
        show(restricted ? "麥克風存取受系統限制" : "麥克風權限未開啟")
        message(restricted ? "麥克風存取受限制" : "需要麥克風權限",
                restricted
                ? "此 Mac 的系統政策限制了麥克風存取，請確認裝置管理或家長監護設定。"
                : "請在系統設定的「隱私權與安全性 → 麥克風」允許 Stan Mic Bridge，再按開始。若系統要求重新開啟程式，請先結束再開啟。")
    }

    private func requestMicrophoneAccess() {
        show("等待麥克風權限")
        let epoch = generation
        AVCaptureDevice.requestAccess(for: .audio) { [weak self] granted in
            DispatchQueue.main.async {
                guard let self = self, self.enabled, self.generation == epoch else { return }
                guard granted else {
                    self.microphoneUnavailable(restricted: AVCaptureDevice.authorizationStatus(for: .audio) == .restricted)
                    return
                }
                self.connect()
            }
        }
    }

    @objc private func stop() {
        enabled = false
        disconnect()
        if let activity = activity { ProcessInfo.processInfo.endActivity(activity) }
        activity = nil
        show("已停止")
    }

    private func connect() {
        guard enabled, !sleeping, let request = connection?.socketRequest else { return }
        guard AVCaptureDevice.authorizationStatus(for: .audio) == .authorized else {
            stop()
            show("請允許麥克風權限後重新開始")
            return
        }
        if activity == nil {
            activity = ProcessInfo.processInfo.beginActivity(options: [.userInitiatedAllowingIdleSystemSleep],
                                                              reason: "Live microphone transmission")
        }
        disconnect()
        let epoch = generation
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        let session = URLSession(configuration: configuration, delegate: NoRedirectDelegate(), delegateQueue: nil)
        self.session = session
        let task = session.webSocketTask(with: request)
        task.maximumMessageSize = 4096
        socket = task
        connectedAt = ProcessInfo.processInfo.systemUptime
        lastSent = connectedAt
        show("連線中")
        task.resume()
        receive(task, epoch: epoch)
        task.send(.string("{\"sampleRate\":48000}")) { [weak self] error in
            DispatchQueue.main.async {
                guard let self = self, self.generation == epoch else { return }
                if error != nil { self.connectionFailed(task) }
            }
        }
        let timer = Timer(timeInterval: 0.01, repeats: true) { [weak self] _ in self?.tick(epoch: epoch) }
        self.timer = timer
        RunLoop.main.add(timer, forMode: .common)
    }

    private func receive(_ task: URLSessionWebSocketTask, epoch: Int) {
        task.receive { [weak self] result in
            DispatchQueue.main.async {
                guard let self = self, self.generation == epoch, self.enabled else { return }
                switch result {
                case .failure:
                    self.connectionFailed(task)
                case .success(let message):
                    guard !self.ready, case .string(let text) = message,
                          let data = text.data(using: .utf8),
                          let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
                          object["ready"] as? Bool == true else {
                        self.scheduleRetry(message: "接收端尚未就緒，正在重試")
                        return
                    }
                    do {
                        try self.beginAudio()
                        self.ready = true
                        self.lastSent = ProcessInfo.processInfo.systemUptime
                        self.show("正在傳送麥克風")
                        self.receive(task, epoch: epoch)
                    } catch {
                        self.scheduleRetry(message: "音訊裝置暫時不可用，正在重試")
                    }
                }
            }
        }
    }

    private func connectionFailed(_ task: URLSessionWebSocketTask) {
        let status = (task.response as? HTTPURLResponse)?.statusCode
        if status == 401 || status == 403 {
            stop()
            show("連線驗證失敗，請重新設定完整連結")
        } else if status == 409 {
            scheduleRetry(message: "另一個麥克風正在傳送，等待它停止")
        } else {
            scheduleRetry(message: "連線中斷，請確認 Tailscale 與接收端已開啟")
        }
    }

    private func beginAudio() throws {
        let engine = AVAudioEngine()
        let input = engine.inputNode
        let source = input.outputFormat(forBus: 0)
        guard source.sampleRate >= 8000, source.sampleRate <= 384000, source.channelCount > 0,
              let target = AVAudioFormat(commonFormat: .pcmFormatFloat32, sampleRate: 48000,
                                         channels: 1, interleaved: false),
              let converter = AVAudioConverter(from: source, to: target) else {
            throw NSError(domain: "StanMicBridge", code: 1)
        }
        let box = AudioMailbox(sourceRate: source.sampleRate)
        self.engine = engine
        mailbox = box
        input.installTap(onBus: 0, bufferSize: 1024, format: source) { buffer, _ in
            box.recordCaptured(Int(buffer.frameLength))
            // Conversion happens before returning the tap's borrowed buffer.
            let needed = Int(ceil(Double(buffer.frameLength) * 48000 / source.sampleRate)) + 64
            guard needed > 0, needed <= 32768,
                  let output = AVAudioPCMBuffer(pcmFormat: target, frameCapacity: AVAudioFrameCount(needed)) else {
                box.fail()
                return
            }
            var supplied = false
            var conversionError: NSError?
            let result = converter.convert(to: output, error: &conversionError) { _, status in
                if supplied { status.pointee = .noDataNow; return nil }
                supplied = true
                status.pointee = .haveData
                return buffer
            }
            guard result != .error, conversionError == nil else { box.fail(); return }
            guard output.frameLength > 0, let samples = output.floatChannelData?[0] else { return }
            box.recordConverted(Int(output.frameLength))
            // All supported Mac CPUs use little endian IEEE-754 float32, matching
            // the receiver's '<f4' protocol. Sanitize unexpected hardware values.
            for i in 0..<Int(output.frameLength) {
                let value = samples[i]
                samples[i] = value.isFinite ? max(-1, min(1, value)) : 0
            }
            // A driver may deliver more frames than the requested tap size.
            // Split into protocol-sized chunks; the mailbox still bounds latency.
            var offset = 0
            while offset < Int(output.frameLength) {
                let count = min(1024, Int(output.frameLength) - offset)
                box.put(Data(bytes: samples.advanced(by: offset), count: count * MemoryLayout<Float>.size))
                offset += count
            }
        }
        engine.prepare()
        try engine.start()
        let epoch = generation
        engineObserver = NotificationCenter.default.addObserver(forName: .AVAudioEngineConfigurationChange,
                                                                object: engine, queue: .main) { [weak self] _ in
            guard let self = self, self.enabled, self.generation == epoch else { return }
            self.scheduleRetry(message: "麥克風裝置已變更，正在重連")
        }
    }

    private func tick(epoch: Int) {
        guard enabled, generation == epoch else { return }
        let now = ProcessInfo.processInfo.systemUptime
        if !ready {
            if now - connectedAt > 7 { scheduleRetry(message: "連線逾時，正在重試") }
            return
        }
        if mailbox?.failed() == true || now - lastSent > 3 || (inFlight && now - sendBegan > 2) {
            scheduleRetry(message: "音訊停滯，正在恢復")
            return
        }
        if now - connectedAt > 30 { failures = 0 }
        sendNext(epoch: epoch)
    }

    private func sendNext(epoch: Int) {
        guard enabled, generation == epoch, ready, !inFlight,
              let task = socket, let packet = mailbox?.take() else { return }
        inFlight = true
        sendBegan = ProcessInfo.processInfo.systemUptime
        task.send(.data(packet.bytes)) { [weak self] error in
            DispatchQueue.main.async {
                guard let self = self, self.generation == epoch else { return }
                self.inFlight = false
                if error != nil { self.scheduleRetry(message: "傳送中斷，正在重試"); return }
                self.lastSent = ProcessInfo.processInfo.systemUptime
                self.mailbox?.recordSent(packet.bytes.count / MemoryLayout<Float>.size)
                self.sendNext(epoch: epoch)
            }
        }
    }

    private func disconnect() {
        generation += 1
        retry?.cancel()
        retry = nil
        timer?.invalidate()
        timer = nil
        if let observer = engineObserver { NotificationCenter.default.removeObserver(observer) }
        engineObserver = nil
        if let engine = engine {
            engine.stop()
            engine.inputNode.removeTap(onBus: 0)
        }
        engine = nil
        if let mailbox = mailbox { lastAudioSnapshot = mailbox.snapshot() }
        mailbox = nil
        ready = false
        inFlight = false
        socket?.cancel(with: .goingAway, reason: nil)
        socket = nil
        session?.invalidateAndCancel()
        session = nil
    }

    private func scheduleRetry(message: String) {
        disconnect()
        guard enabled else { return }
        guard !sleeping else { show("睡眠中，喚醒後重連"); return }
        failures = min(failures + 1, 8)
        // 2, 4, 8, 16, 30 seconds, capped; no spin or overlapping attempts.
        let delay = min(30.0, pow(2.0, Double(min(failures, 5))))
        show(message + "（\(Int(delay)) 秒）")
        let epoch = generation
        let work = DispatchWorkItem { [weak self] in
            guard let self = self, self.enabled, !self.sleeping, self.generation == epoch else { return }
            self.connect()
        }
        retry = work
        DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: work)
    }

    @objc private func quitApp() { stop(); NSApp.terminate(nil) }

    func applicationWillTerminate(_ notification: Notification) {
        stop()
        updateSession?.invalidateAndCancel()
        if !installerHandoff, let root = stagingRoot { try? FileManager.default.removeItem(at: root) }
        for observer in workspaceObservers { NSWorkspace.shared.notificationCenter.removeObserver(observer) }
    }
}

@main
private struct StanMicBridgeMain {
    static func main() {
        if CommandLine.arguments.contains("--test-updates") {
            testUpdatePolicy()
            exit(0)
        }

        // CI validates the exact release ZIP using the same staging path as the UI.
        if CommandLine.arguments.count == 5, CommandLine.arguments[1] == "--test-update-package" {
            let root = FileManager.default.temporaryDirectory.appendingPathComponent("StanMicBridge-update-" + UUID().uuidString)
            do {
                let archive = URL(fileURLWithPath: CommandLine.arguments[2])
                let tag = CommandLine.arguments[3]
                let size = try archive.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
                var release = PublicRelease(tag_name: tag,
                    html_url: "https://github.com/stantheman0128/stan-mic-bridge/releases/tag/" + tag,
                    body: nil, draft: false, prerelease: false)
                release.assets = [.init(name: "StanMicBridge-macOS.zip",
                    browser_download_url: "https://github.com/stantheman0128/stan-mic-bridge/releases/download/" + tag + "/StanMicBridge-macOS.zip",
                    digest: "sha256:" + CommandLine.arguments[4], size: size)]
                guard release.installAsset != nil else { throw InstallFailure.invalid }
                try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
                _ = try UpdateStaging.prepare(Data(contentsOf: archive), release: release, root: root)
                try FileManager.default.removeItem(at: root)
                print("Update package validation passed")
                exit(0)
            } catch {
                try? FileManager.default.removeItem(at: root)
                print("Update package validation failed")
                exit(1)
            }
        }

        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        app.run()
    }
}
