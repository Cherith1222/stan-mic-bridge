import Foundation
import Security
import CryptoKit
import Darwin

// A per-user identity stabilizes this user's app requirement across upgrades.
// It does not confer Developer ID trust or grant microphone/Keychain permission.
enum LocalSigning {
    struct Failure: Error, LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }
    struct Configuration: Codable {
        let schema: Int
        let certificateSHA1: String
        let keychainPath: String
        let label: String
        let createdAt: Double
    }
    struct Context {
        let anchor: URL
        let directory: URL
        var configurationURL: URL { directory.appendingPathComponent("identity.json") }
        // Used only by isolated tests. Production obtains the user's default keychain.
        var creationKeychain: SecKeychain? = nil
    }
    static let appIdentifier = "com.stan.micbridge"
    static let helperIdentifier = "com.stan.micbridge.updater"
    static let fileManager = FileManager.default
    static func require(_ condition: Bool, _ message: String) throws {
        if !condition { throw Failure(message: message) }
    }
    static func check(_ status: OSStatus, _ operation: String) throws {
        if status != errSecSuccess {
            let description = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
            throw Failure(message: "\(operation): \(description). The installed app was not replaced.")
        }
    }
    static func productionContext() -> Context {
        let home = fileManager.homeDirectoryForCurrentUser
        return Context(anchor: home,
                       directory: home.appendingPathComponent("Library/Application Support/StanMicBridge/LocalSigning"))
    }
    static func canonical(_ path: URL) throws -> URL {
        guard let result = realpath(path.path, nil) else { throw Failure(message: "A local signing directory is unavailable.") }
        defer { free(result) }
        return URL(fileURLWithPath: String(cString: result))
    }
    // Canonicalize only a trusted anchor. Walk candidate descendants with lstat;
    // never hide a user-created link by resolving the whole candidate.
    @discardableResult static func stateDirectory(_ context: Context, create: Bool) throws -> URL? {
        let canonicalAnchor = try canonical(context.anchor)
        let prefixes = [context.anchor.path, canonicalAnchor.path].map { $0.hasSuffix("/") ? String($0.dropLast()) : $0 }
        guard let prefix = prefixes.first(where: { context.directory.path.hasPrefix($0 + "/") }) else {
            throw Failure(message: "The signing state directory is outside the current user's directory.")
        }
        let parts = context.directory.path.dropFirst(prefix.count + 1).split(separator: "/", omittingEmptySubsequences: false)
        try require(!parts.isEmpty && parts.allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." }, "Invalid signing state directory.")
        var current = canonicalAnchor.path
        for part in parts {
            current += "/" + String(part)
            var metadata = stat()
            if lstat(current, &metadata) != 0 {
                try require(errno == ENOENT, "The signing state directory cannot be inspected.")
                if !create { return nil }
                try require(mkdir(current, 0o700) == 0, "The signing state directory could not be created.")
                try require(lstat(current, &metadata) == 0, "The signing state directory could not be inspected.")
            }
            try require(metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR), "A signing state path component is not a real directory.")
        }
        var metadata = stat()
        try require(lstat(current, &metadata) == 0 && metadata.st_uid == geteuid() && metadata.st_mode & 0o077 == 0,
                    "The signing state directory must be private and owned by the current user.")
        return URL(fileURLWithPath: current)
    }
    static func loadConfiguration(_ context: Context) throws -> Configuration? {
        guard let directory = try stateDirectory(context, create: false) else { return nil }
        let path = directory.appendingPathComponent("identity.json")
        var metadata = stat()
        if lstat(path.path, &metadata) != 0 {
            try require(errno == ENOENT, "The signing configuration cannot be inspected.")
            return nil
        }
        try require(metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG)
                    && metadata.st_uid == geteuid() && metadata.st_mode & 0o077 == 0
                    && metadata.st_size > 0 && metadata.st_size <= 16384,
                    "The local signing configuration is not a private regular file.")
        let config = try JSONDecoder().decode(Configuration.self, from: Data(contentsOf: path))
        try require(config.schema == 1 && config.certificateSHA1.count == 40
                    && config.certificateSHA1.allSatisfy { $0.isHexDigit }
                    && config.keychainPath.hasPrefix("/") && !config.label.isEmpty,
                    "The local signing configuration is invalid. Re-run explicit local-signing setup to repair it.")
        return config
    }
    static func saveConfiguration(_ config: Configuration, context: Context) throws {
        guard let directory = try stateDirectory(context, create: true) else { throw Failure(message: "Missing signing state directory.") }
        let path = directory.appendingPathComponent("identity.json")
        try JSONEncoder().encode(config).write(to: path, options: .atomic)
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
    }
    static func requirement(identifier: String, fingerprint: String) -> String {
        "identifier \"\(identifier)\" and certificate leaf = H\"\(fingerprint.lowercased())\""
    }
    static func staticCode(_ app: URL) throws -> SecStaticCode {
        var code: SecStaticCode?
        try check(SecStaticCodeCreateWithPath(app as CFURL, [], &code), "Read code signature")
        guard let result = code else { throw Failure(message: "The app has no static code object.") }
        return result
    }
    static func certificateFingerprint(_ app: URL) throws -> String? {
        var info: CFDictionary?
        try check(SecCodeCopySigningInformation(try staticCode(app), SecCSFlags(rawValue: kSecCSSigningInformation), &info), "Read signing certificate")
        guard let dictionary = info as? [String: Any],
              let certificates = dictionary[kSecCodeInfoCertificates as String] as? [SecCertificate],
              let certificate = certificates.first else { return nil }
        return Insecure.SHA1.hash(data: SecCertificateCopyData(certificate) as Data)
            .map { String(format: "%02x", $0) }.joined()
    }
    static func designatedRequirement(_ app: URL) throws -> SecRequirement {
        var requirement: SecRequirement?
        try check(SecCodeCopyDesignatedRequirement(try staticCode(app), [], &requirement), "Read designated requirement")
        guard let result = requirement else { throw Failure(message: "The app has no designated requirement.") }
        return result
    }
    static func requirementData(_ requirement: SecRequirement) throws -> Data {
        var data: CFData?
        try check(SecRequirementCopyData(requirement, [], &data), "Encode designated requirement")
        guard let result = data else { throw Failure(message: "The designated requirement could not be encoded.") }
        return result as Data
    }
    static func checkCode(_ app: URL, satisfies requirement: SecRequirement? = nil) throws {
        try check(SecStaticCodeCheckValidity(try staticCode(app), SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures), requirement), "Validate signed code")
    }
    static func explicitRequirement(_ text: String) throws -> SecRequirement {
        var result: SecRequirement?
        try check(SecRequirementCreateWithString(text as CFString, [], &result), "Build signing requirement")
        guard let requirement = result else { throw Failure(message: "The signing requirement could not be built.") }
        return requirement
    }
    static func verifyPinned(_ app: URL, config: Configuration, identifier: String) throws {
        try require(try certificateFingerprint(app) == config.certificateSHA1.lowercased(),
                    "The installed app's certificate does not match the pinned local identity. Update cancelled.")
        let expected = try explicitRequirement(requirement(identifier: identifier, fingerprint: config.certificateSHA1))
        try checkCode(app, satisfies: expected)
        try require(try requirementData(designatedRequirement(app)) == requirementData(expected),
                    "The app's designated requirement differs from the pinned local identity. Update cancelled.")
    }
    static func helperURL(_ app: URL) -> URL { app.appendingPathComponent("Contents/Helpers/StanMicUpdater") }
    static func verifyPinnedApp(_ app: URL, config: Configuration) throws {
        try verifyPinned(app, config: config, identifier: appIdentifier)
        try verifyPinned(helperURL(app), config: config, identifier: helperIdentifier)
        try run("/usr/bin/codesign", ["--verify", "--deep", "--strict", app.path])
    }
    static func ensureContinuity(old: URL, new: URL) throws {
        for pair in [(old, new), (helperURL(old), helperURL(new))] {
            let oldRequirement = try designatedRequirement(pair.0)
            try checkCode(pair.1, satisfies: oldRequirement)
            try require(try requirementData(oldRequirement) == requirementData(designatedRequirement(pair.1)),
                        "The update changed a designated requirement. The installed app was retained.")
        }
    }
    static func openKeychain(_ path: String) throws -> SecKeychain {
        var keychain: SecKeychain?
        try check(SecKeychainOpen(path, &keychain), "Open local signing keychain")
        guard let result = keychain else { throw Failure(message: "The local signing keychain is unavailable.") }
        return result
    }
    static func keychainPath(_ keychain: SecKeychain) throws -> String {
        var count: UInt32 = 4096
        var bytes = [CChar](repeating: 0, count: Int(count))
        try check(SecKeychainGetPath(keychain, &count, &bytes), "Read signing keychain path")
        return String(cString: bytes)
    }
    static func requireIdentity(_ config: Configuration) throws {
        let keychain = try openKeychain(config.keychainPath)
        let query: [String: Any] = [kSecClass as String: kSecClassIdentity,
                                    kSecMatchSearchList as String: [keychain],
                                    kSecReturnRef as String: true,
                                    kSecMatchLimit as String: kSecMatchLimitAll]
        var found: CFTypeRef?
        try check(SecItemCopyMatching(query as CFDictionary, &found), "Find the pinned local signing identity")
        guard let identities = found as? [SecIdentity] else { throw Failure(message: "The pinned signing identity is missing. No ad-hoc fallback is permitted.") }
        for identity in identities {
            var certificate: SecCertificate?
            if SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate = certificate {
                let fingerprint = Insecure.SHA1.hash(data: SecCertificateCopyData(certificate) as Data)
                    .map { String(format: "%02x", $0) }.joined()
                if fingerprint == config.certificateSHA1.lowercased() { return }
            }
        }
        throw Failure(message: "The pinned signing identity is missing. No ad-hoc fallback is permitted.")
    }
    static func sign(_ path: URL, identifier: String, config: Configuration) throws {
        try run("/usr/bin/codesign", ["--force", "--sign", config.certificateSHA1,
            "--keychain", config.keychainPath, "--identifier", identifier, "--timestamp=none",
            "--requirements", "designated => " + requirement(identifier: identifier, fingerprint: config.certificateSHA1), path.path], timeout: 120)
        try verifyPinned(path, config: config, identifier: identifier)
    }
    static func signApp(_ app: URL, config: Configuration) throws {
        try requireIdentity(config)
        try sign(helperURL(app), identifier: helperIdentifier, config: config)
        try sign(app, identifier: appIdentifier, config: config)
        try verifyPinnedApp(app, config: config)
    }
    static func isEnabled(for app: URL) throws -> Bool {
        guard let config = try loadConfiguration(productionContext()) else {
            try require(try certificateFingerprint(app) == nil && certificateFingerprint(helperURL(app)) == nil, "The app is certificate-signed but its local signing configuration is missing. Updates will stop until it is restored.")
            return false
        }
        try verifyPinnedApp(app, config: config)
        return true
    }
    static func prepareDownloadedApp(at downloaded: URL, installedApp: URL, context supplied: Context? = nil) throws {
        let context = supplied ?? productionContext()
        // Always verify downloaded code before any local signature is applied.
        try run("/usr/bin/codesign", ["--verify", "--deep", "--strict", downloaded.path])
        guard let config = try loadConfiguration(context) else {
            try require(try certificateFingerprint(installedApp) == nil && certificateFingerprint(helperURL(installedApp)) == nil, "Local signing configuration is missing. The certificate-signed installed app will not be replaced.")
            return
        }
        try verifyPinnedApp(installedApp, config: config)
        try requireIdentity(config)
        if (try certificateFingerprint(downloaded)) != config.certificateSHA1.lowercased() {
            try signApp(downloaded, config: config)
        }
        try verifyPinnedApp(downloaded, config: config)
        try ensureContinuity(old: installedApp, new: downloaded)
    }
    static func prepareInstallerApp(at staged: URL, installedApp: URL?, context supplied: Context? = nil) throws {
        let context = supplied ?? productionContext()
        if let installed = installedApp {
            try prepareDownloadedApp(at: staged, installedApp: installed, context: context)
        } else {
            try run("/usr/bin/codesign", ["--verify", "--deep", "--strict", staged.path])
            if let config = try loadConfiguration(context) { try signApp(staged, config: config) }
        }
    }
    static func setup(app: URL, context supplied: Context? = nil) throws {
        let context = supplied ?? productionContext()
        try run("/usr/bin/codesign", ["--verify", "--deep", "--strict", app.path])
        if let config = try loadConfiguration(context) {
            // Explicit setup reuses, never silently rotates, an existing identity.
            try signApp(app, config: config)
            return
        }
        if supplied == nil {
            let installed = fileManager.homeDirectoryForCurrentUser.appendingPathComponent("Applications/Stan Mic Bridge.app")
            if fileManager.fileExists(atPath: installed.path) {
                try require(try certificateFingerprint(installed) == nil,
                            "The installed app is already certificate-signed but its local configuration is missing. Recover the original identity/configuration instead of creating a replacement identity.")
            }
        }
        let config = try createIdentity(context: context)
        // Pin first so cancellation cannot cause a different identity next time.
        // Only the installer staging copy is ever changed by setup.
        try saveConfiguration(config, context: context)
        try signApp(app, config: config)
    }
    static func createIdentity(context: Context) throws -> Configuration {
        _ = try stateDirectory(context, create: true)
        let keychain: SecKeychain
        if let provided = context.creationKeychain { keychain = provided }
        else {
            var defaultKeychain: SecKeychain?
            try check(SecKeychainCopyDefault(&defaultKeychain), "Open the user's default keychain")
            guard let selected = defaultKeychain else { throw Failure(message: "No user keychain is available.") }
            keychain = selected
            let path = try canonical(URL(fileURLWithPath: keychainPath(selected)))
            let home = try canonical(fileManager.homeDirectoryForCurrentUser)
            try require(path.path.hasPrefix(home.path + "/"), "Local signing must use a keychain inside the current user's home.")
        }
        let root = fileManager.temporaryDirectory.appendingPathComponent("StanMicBridge-signing-\(UUID().uuidString)")
        try fileManager.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? fileManager.removeItem(at: root) }
        let label = "Stan Mic Bridge Local " + UUID().uuidString
        let key = root.appendingPathComponent("key.pem")
        let cert = root.appendingPathComponent("certificate.pem")
        let der = root.appendingPathComponent("certificate.der")
        let p12 = root.appendingPathComponent("identity.p12")
        let openssl = root.appendingPathComponent("openssl.cnf")
        let configuration = """
        [req]
        distinguished_name = subject
        x509_extensions = code_signing
        prompt = no
        [subject]
        CN = \(label)
        [code_signing]
        basicConstraints = critical,CA:FALSE
        keyUsage = critical,digitalSignature
        extendedKeyUsage = critical,codeSigning
        subjectKeyIdentifier = hash
        """
        try configuration.write(to: openssl, atomically: true, encoding: .utf8)
        // Temporary key files are private even before OpenSSL opens them.
        try Data().write(to: key)
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: key.path)
        try run("/usr/bin/openssl", ["req", "-new", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "3650", "-sha256",
            "-config", openssl.path, "-keyout", key.path, "-out", cert.path], timeout: 60)
        try run("/usr/bin/openssl", ["x509", "-in", cert.path, "-outform", "DER", "-out", der.path])
        let passphrase = UUID().uuidString + UUID().uuidString
        try run("/usr/bin/openssl", ["pkcs12", "-export", "-inkey", key.path, "-in", cert.path,
            "-name", label, "-out", p12.path, "-passout", "stdin"], input: Data((passphrase + "\n").utf8))
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: p12.path)
        var trusted: SecTrustedApplication?
        try check(SecTrustedApplicationCreateFromPath("/usr/bin/codesign", &trusted), "Set codesign-only private key access")
        guard let codesign = trusted else { throw Failure(message: "The Apple codesign tool is unavailable.") }
        var access: SecAccess?
        try check(SecAccessCreate(label as CFString, [codesign] as CFArray, &access), "Create private key access control")
        guard let acl = access else { throw Failure(message: "Private key access control could not be created.") }
        let attributes = [kSecAttrIsPermanent, kSecAttrIsSensitive] as CFArray // Deliberately not extractable.
        let usage = [kSecAttrCanSign] as CFArray
        let password = passphrase as CFString
        var parameters = SecItemImportExportKeyParameters()
        parameters.version = UInt32(SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION)
        parameters.passphrase = Unmanaged.passUnretained(password)
        parameters.accessRef = Unmanaged.passUnretained(acl)
        parameters.keyAttributes = Unmanaged.passUnretained(attributes)
        parameters.keyUsage = Unmanaged.passUnretained(usage)
        var format = SecExternalFormat.formatPKCS12
        var type = SecExternalItemType.itemTypeAggregate
        var imported: CFArray?
        try check(SecItemImport(try Data(contentsOf: p12) as CFData, "identity.p12" as CFString,
                               &format, &type, [], &parameters, keychain, &imported), "Import the local non-extractable signing identity")
        let fingerprint = Insecure.SHA1.hash(data: try Data(contentsOf: der)).map { String(format: "%02x", $0) }.joined()
        let config = Configuration(schema: 1, certificateSHA1: fingerprint, keychainPath: try keychainPath(keychain),
                                   label: label, createdAt: Date().timeIntervalSince1970)
        try requireIdentity(config)
        return config
    }
    // Never pass passwords/private keys in command arguments or log tool output.
    static func run(_ executable: String, _ arguments: [String], input: Data? = nil, timeout: TimeInterval = 30) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        let pipe = Pipe()
        process.standardInput = pipe
        try process.run()
        if let data = input { pipe.fileHandleForWriting.write(data) }
        try? pipe.fileHandleForWriting.close()
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        while process.isRunning && ProcessInfo.processInfo.systemUptime < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }
        if process.isRunning {
            process.terminate()
            throw Failure(message: "\(URL(fileURLWithPath: executable).lastPathComponent) timed out. The installed app was retained.")
        }
        try require(process.terminationStatus == 0,
                    "\(URL(fileURLWithPath: executable).lastPathComponent) failed or was cancelled (exit \(process.terminationStatus)). The installed app was retained.")
    }
}
