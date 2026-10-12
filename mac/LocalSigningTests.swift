import Foundation
import Security
import CryptoKit
import Darwin

// Executed only by --test-local-signing. No production keychain, trust settings,
// app installation, microphone entitlement, or receiver credential is changed.
enum LocalSigningTests {
    static func run(app source: URL) throws {
        let files = FileManager.default
        let root = files.temporaryDirectory.appendingPathComponent("StanMicBridge-signing-test-\(UUID().uuidString)")
        try files.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? files.removeItem(at: root) }
        let keychainURL = root.appendingPathComponent("test.keychain-db")
        let password = UUID().uuidString + UUID().uuidString
        var created: SecKeychain?
        let result = password.withCString { pointer in
            SecKeychainCreate(keychainURL.path, UInt32(password.utf8.count), pointer, false, nil, &created)
        }
        try LocalSigning.check(result, "Create isolated test keychain")
        guard let keychain = created else { throw LocalSigning.Failure(message: "The test keychain was not created.") }
        var keychainDeleted = false
        defer { if !keychainDeleted { SecKeychainDelete(keychain) } }
        // Test processes must fail instead of opening a permission dialog on CI.
        SecKeychainSetUserInteractionAllowed(false)
        let context = LocalSigning.Context(anchor: root, directory: root.appendingPathComponent("state"), creationKeychain: keychain)
        let config = try LocalSigning.createIdentity(context: context)
        try LocalSigning.saveConfiguration(config, context: context)
        // The disposable keychain contains exactly one private key. This permits
        // Apple codesign in this test keychain only; production never runs this.
        try LocalSigning.run("/usr/bin/security", ["set-key-partition-list", "-S", "apple-tool:,apple:",
            "-l", config.label, "-s", "-k", password, config.keychainPath])
        try assertNonExtractable(config: config)
        print("Local signing: isolated identity imported; private key is non-extractable.")
        let oldApp = root.appendingPathComponent("old/Stan Mic Bridge.app")
        let newApp = root.appendingPathComponent("new/Stan Mic Bridge.app")
        try files.createDirectory(at: oldApp.deletingLastPathComponent(), withIntermediateDirectories: false)
        try files.createDirectory(at: newApp.deletingLastPathComponent(), withIntermediateDirectories: false)
        try files.copyItem(at: source, to: oldApp)
        try files.copyItem(at: source, to: newApp)
        let infoURL = oldApp.appendingPathComponent("Contents/Info.plist")
        guard var info = try PropertyListSerialization.propertyList(from: Data(contentsOf: infoURL), options: [], format: nil) as? [String: Any],
              let text = info["CFBundleVersion"] as? String, let build = Int(text), build > 1 else {
            throw LocalSigning.Failure(message: "The signing fixture needs a valid build greater than one.")
        }
        info["CFBundleVersion"] = String(build - 1)
        try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: infoURL)
        try LocalSigning.run("/usr/bin/codesign", ["--force", "--sign", "-", oldApp.path])
        try LocalSigning.setup(app: oldApp, context: context)
        let originalExecutable = try Data(contentsOf: oldApp.appendingPathComponent("Contents/MacOS/StanMicBridge"))
        try LocalSigning.prepareDownloadedApp(at: newApp, installedApp: oldApp, context: context)
        try LocalSigning.verifyPinnedApp(oldApp, config: config)
        try LocalSigning.verifyPinnedApp(newApp, config: config)
        try LocalSigning.ensureContinuity(old: oldApp, new: newApp)
        try LocalSigning.require(try Data(contentsOf: oldApp.appendingPathComponent("Contents/MacOS/StanMicBridge")) == originalExecutable,
                                 "Preparing the new app changed the installed fixture.")
        print("Local signing: two app builds preserve exact app and helper designated requirements.")
        try keychainContinuity(root: root, config: config)
        // A bad pin, missing configuration, and deleted identity all fail closed.
        let bad = LocalSigning.Configuration(schema: 1, certificateSHA1: String(repeating: "0", count: 40),
            keychainPath: config.keychainPath, label: config.label, createdAt: config.createdAt)
        try LocalSigning.saveConfiguration(bad, context: context)
        try expectFailure("mismatched certificate pin") {
            try LocalSigning.prepareDownloadedApp(at: newApp, installedApp: oldApp, context: context)
        }
        try LocalSigning.saveConfiguration(config, context: context)
        try files.removeItem(at: context.configurationURL)
        try expectFailure("missing local signing configuration") {
            try LocalSigning.prepareDownloadedApp(at: newApp, installedApp: oldApp, context: context)
        }
        try LocalSigning.saveConfiguration(config, context: context)
        try LocalSigning.check(SecKeychainDelete(keychain), "Delete the isolated signing identity")
        keychainDeleted = true
        try expectFailure("missing local signing identity") {
            try LocalSigning.prepareDownloadedApp(at: newApp, installedApp: oldApp, context: context)
        }
        try LocalSigning.require(try Data(contentsOf: oldApp.appendingPathComponent("Contents/MacOS/StanMicBridge")) == originalExecutable,
                                 "A failed update changed the installed fixture.")
        print("Local signing: bad pin, missing configuration and missing identity fail closed; original fixture retained.")
        print("Local signing integration tests passed. No TCC permission grant or microphone capture was attempted.")
    }
    static func expectFailure(_ label: String, action: () throws -> Void) throws {
        var rejected = false
        do { try action() } catch { rejected = true }
        try LocalSigning.require(rejected, "The signing test unexpectedly accepted \(label).")
    }
    static func assertNonExtractable(config: LocalSigning.Configuration) throws {
        let keychain = try LocalSigning.openKeychain(config.keychainPath)
        let query: [String: Any] = [kSecClass as String: kSecClassIdentity, kSecMatchSearchList as String: [keychain],
                                    kSecMatchLimit as String: kSecMatchLimitOne, kSecReturnRef as String: true]
        var result: CFTypeRef?
        try LocalSigning.check(SecItemCopyMatching(query as CFDictionary, &result), "Read isolated test identity")
        guard let result = result, CFGetTypeID(result) == SecIdentityGetTypeID() else {
            throw LocalSigning.Failure(message: "The isolated identity was not found.")
        }
        let identity = unsafeBitCast(result, to: SecIdentity.self)
        var key: SecKey?
        try LocalSigning.check(SecIdentityCopyPrivateKey(identity, &key), "Read test key attributes")
        guard let privateKey = key, let attributes = SecKeyCopyAttributes(privateKey) as? [String: Any] else {
            throw LocalSigning.Failure(message: "Private key attributes are unavailable.")
        }
        try LocalSigning.require(attributes[kSecAttrIsExtractable as String] as? Bool == false,
                                 "The imported key is extractable.")
        var exported: CFData?
        let status = SecItemExport(privateKey, .formatPEMSequence, [], nil, &exported)
        try LocalSigning.require(status != errSecSuccess && exported == nil,
                                 "The non-extractable private key was unexpectedly exported.")
    }
    static func keychainContinuity(root: URL, config: LocalSigning.Configuration) throws {
        let source = root.appendingPathComponent("probe.swift")
        let first = root.appendingPathComponent("probe-v1")
        let second = root.appendingPathComponent("probe-v2")
        let wrong = root.appendingPathComponent("probe-wrong-signer")
        let service = "com.stan.micbridge.signing-test." + UUID().uuidString
        let code = #"""
        import Foundation
        import Security
        import Darwin
        let generation = "__GENERATION__"
        let arguments = CommandLine.arguments
        guard arguments.count == 4 else { exit(2) }
        SecKeychainSetUserInteractionAllowed(false)
        var keychain: SecKeychain?
        guard SecKeychainOpen(arguments[2], &keychain) == errSecSuccess, let chain = keychain else { exit(3) }
        let service = arguments[3]
        let account = "continuity"
        let value = "local-signing-continuity"
        let status: OSStatus = service.withCString { servicePointer in
            account.withCString { accountPointer in
                if arguments[1] == "write" {
                    return value.withCString { valuePointer in
                        SecKeychainAddGenericPassword(chain, UInt32(service.utf8.count), servicePointer,
                            UInt32(account.utf8.count), accountPointer, UInt32(value.utf8.count), valuePointer, nil)
                    }
                }
                var length: UInt32 = 0
                var bytes: UnsafeMutableRawPointer?
                let found = SecKeychainFindGenericPassword(chain, UInt32(service.utf8.count), servicePointer,
                    UInt32(account.utf8.count), accountPointer, &length, &bytes, nil)
                guard found == errSecSuccess, let pointer = bytes else { return found == errSecSuccess ? errSecDecode : found }
                defer { SecKeychainItemFreeContent(nil, pointer) }
                return Data(bytes: pointer, count: Int(length)) == Data(value.utf8) ? errSecSuccess : errSecDecode
            }
        }
        guard status == errSecSuccess else { fputs("probe OSStatus \(status)\n", stderr); exit(4) }
        print("probe generation \(generation) succeeded")
        """#
        for (generation, output) in [("first-distinct-build", first), ("second-distinct-build", second)] {
            try code.replacingOccurrences(of: "__GENERATION__", with: generation).write(to: source, atomically: true, encoding: .utf8)
            try LocalSigning.run("/usr/bin/xcrun", ["swiftc", "-swift-version", "5", "-O", "-framework", "Security", source.path, "-o", output.path], timeout: 90)
            try LocalSigning.sign(output, identifier: "com.stan.micbridge.signing-probe", config: config)
        }
        try LocalSigning.require(try Data(contentsOf: first) != Data(contentsOf: second), "The two code-signing probes are identical.")
        let oldRequirement = try LocalSigning.designatedRequirement(first)
        try LocalSigning.checkCode(second, satisfies: oldRequirement)
        try LocalSigning.require(try LocalSigning.requirementData(oldRequirement) == LocalSigning.requirementData(LocalSigning.designatedRequirement(second)),
                                 "Distinct probe builds changed designated requirement.")
        try LocalSigning.run(first.path, ["write", config.keychainPath, service])
        try LocalSigning.run(second.path, ["read", config.keychainPath, service])
        try FileManager.default.copyItem(at: second, to: wrong)
        try LocalSigning.run("/usr/bin/codesign", ["--force", "--sign", "-", "--identifier", "com.stan.micbridge.signing-probe", wrong.path])
        try expectFailure("a differently signed Keychain reader") {
            try LocalSigning.run(wrong.path, ["read", config.keychainPath, service])
        }
        print("Local signing: two distinct signed probe binaries share their own Keychain item; wrong signer denied without prompting.")
    }
}
