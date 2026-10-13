import Foundation
import Security
import CryptoKit
import Darwin

// Executed only by --test-local-signing. No production keychain, trust settings,
// app installation, microphone entitlement, or receiver credential is changed.
enum LocalSigningTests {
    static func run(app source: URL, brokerSources: URL? = nil) throws {
        let files = FileManager.default
        let root = files.temporaryDirectory.appendingPathComponent("StanMicBridge-signing-test-\(UUID().uuidString)")
        try files.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? files.removeItem(at: root) }
        // securityd upgrades keychains to partition enforcement only under the
        // user's Library/Keychains directory. A /tmp fixture can silently test
        // the older ACL format and incorrectly imply update continuity.
        let keychainDirectory = files.homeDirectoryForCurrentUser.appendingPathComponent("Library/Keychains")
        let keychainURL = keychainDirectory.appendingPathComponent("StanMicBridge-isolated-test-\(UUID().uuidString).keychain-db")
        let password = UUID().uuidString + UUID().uuidString
        var originalSearchList: CFArray?
        try LocalSigning.check(SecKeychainCopySearchList(&originalSearchList), "Save the test keychain search list")
        guard let savedSearchList = originalSearchList, let existing = savedSearchList as? [SecKeychain] else {
            throw LocalSigning.Failure(message: "The keychain search list could not be saved.")
        }
        defer { SecKeychainSetSearchList(savedSearchList) }
        var created: SecKeychain?
        let result = password.withCString { pointer in
            SecKeychainCreate(keychainURL.path, UInt32(password.utf8.count), pointer, false, nil, &created)
        }
        try LocalSigning.check(result, "Create isolated test keychain")
        guard let keychain = created else { throw LocalSigning.Failure(message: "The test keychain was not created.") }
        var keychainDeleted = false
        defer { if !keychainDeleted { SecKeychainDelete(keychain) } }
        // codesign's certificate/private-key lookup also consults the user's
        // search list, even with --keychain. Unlike the production default
        // keychain, a newly created isolated fixture is not necessarily listed.
        var afterCreation: CFArray?
        try LocalSigning.check(SecKeychainCopySearchList(&afterCreation), "Inspect the newly created test keychain's search registration")
        let listedAfterCreation = afterCreation as? [SecKeychain] ?? []
        let alreadyListed = listedAfterCreation.contains { (try? LocalSigning.keychainPath($0)) == (try? LocalSigning.keychainPath(keychain)) }
        print("Local signing diagnostic: isolated keychain initially in search list = \(alreadyListed)")
        try LocalSigning.check(SecKeychainSetSearchList(([keychain] + existing) as CFArray), "Register only the isolated test keychain")
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
        try publicIdentityDiagnostic(config: config)
        try oldSignerMetadataDiagnostic(source: source, root: root, config: config)
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
        let previousAdHoc = root.appendingPathComponent("previous-ad-hoc.app")
        try files.copyItem(at: source, to: previousAdHoc)
        // Identity exists but the installed fixture is still ad-hoc: an
        // interrupted first setup may retry without adopting any old pin.
        try LocalSigning.setup(app: oldApp, context: context, installedApp: previousAdHoc)
        let originalExecutable = try Data(contentsOf: oldApp.appendingPathComponent("Contents/MacOS/StanMicBridge"))
        let fixedBroker = context.anchor.appendingPathComponent("credentialBroker/v1/StanMicCredentialBroker")
        let originalBroker = try Data(contentsOf: fixedBroker)
        let pinRelative = "Contents/Resources/CredentialBrokerPin.json"
        let originalPin = try Data(contentsOf: oldApp.appendingPathComponent(pinRelative))
        func pinMatches(_ app: URL) throws -> Bool {
            guard let expected = try JSONSerialization.jsonObject(with: originalPin) as? NSDictionary else { return false }
            return expected.isEqual(try JSONSerialization.jsonObject(with: Data(contentsOf: app.appendingPathComponent(pinRelative))))
        }
        let reinstall = root.appendingPathComponent("reinstall/Stan Mic Bridge.app")
        try files.createDirectory(at: reinstall.deletingLastPathComponent(), withIntermediateDirectories: false)
        try files.copyItem(at: source, to: reinstall)
        try LocalSigning.setup(app: reinstall, context: context, installedApp: oldApp)
        try LocalSigning.require(try pinMatches(reinstall)
            && Data(contentsOf: fixedBroker) == originalBroker,
            "Repeating explicit setup changed the frozen broker or failed to retain its sealed pin.")
        try LocalSigning.prepareDownloadedApp(at: newApp, installedApp: oldApp, context: context)
        // The running app and replacement helper both prepare a download. The
        // second pass must retain the same sealed pin and immutable broker bytes.
        try LocalSigning.prepareDownloadedApp(at: newApp, installedApp: oldApp, context: context)
        try LocalSigning.verifyPinnedApp(oldApp, config: config)
        try LocalSigning.verifyPinnedApp(newApp, config: config)
        try LocalSigning.ensureContinuity(old: oldApp, new: newApp)
        try LocalSigning.require(try Data(contentsOf: oldApp.appendingPathComponent("Contents/MacOS/StanMicBridge")) == originalExecutable,
                                 "Preparing the new app changed the installed fixture.")
        try LocalSigning.require(try Data(contentsOf: fixedBroker) == originalBroker
            && pinMatches(newApp),
            "Update preparation changed the frozen broker or its authenticated app pin.")
        print("Local signing: two app builds preserve exact app and helper designated requirements.")
        print("Two update preparation passes preserve frozen broker bytes and the app-sealed pin.")
        try keychainContinuity(root: root, config: config)
        if let sources = brokerSources {
            try CredentialBrokerTests.run(root: root, config: config, sources: sources, password: password)
        }
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
        print("Direct self-signed client Keychain-read denial was reproduced; frozen-broker continuity is verified separately when broker fixtures are requested. No TCC permission grant or microphone capture was attempted.")
    }
    static func oldSignerMetadataDiagnostic(source: URL, root: URL, config: LocalSigning.Configuration) throws {
        let clone = root.appendingPathComponent("old-signer-diagnostic.app")
        try FileManager.default.copyItem(at: source, to: clone)
        // Exact 1.3.5 signing arguments. Do not assume metadata survives merely
        // because the input release was built with runtime/audio entitlements.
        for (path, identifier) in [(LocalSigning.helperURL(clone), LocalSigning.helperIdentifier),
                                   (clone, LocalSigning.appIdentifier)] {
            try LocalSigning.run("/usr/bin/codesign", ["--force", "--sign", config.certificateSHA1,
                "--keychain", config.keychainPath, "--identifier", identifier, "--timestamp=none",
                "--requirements", "=designated => " + LocalSigning.requirement(identifier: identifier, fingerprint: config.certificateSHA1), path.path])
        }
        func inspect(_ path: URL) throws -> (runtime: Bool, audio: Bool) {
            var output: CFDictionary?
            try LocalSigning.check(SecCodeCopySigningInformation(try LocalSigning.staticCode(path),
                SecCSFlags(rawValue: kSecCSSigningInformation), &output), "Inspect old-signer metadata fixture")
            guard let info = output as? [String: Any], let flags = info[kSecCodeInfoFlags as String] as? NSNumber else {
                throw LocalSigning.Failure(message: "Missing signature flags in old-signer fixture.")
            }
            let entitlements = info[kSecCodeInfoEntitlementsDict as String] as? [String: Any] ?? [:]
            return (flags.uint32Value & 0x10000 != 0, entitlements["com.apple.security.device.audio-input"] as? Bool == true)
        }
        try LocalSigning.verifyPinnedApp(clone, config: config)
        let oldMain = try inspect(clone)
        let oldHelper = try inspect(LocalSigning.helperURL(clone))
        print("Exact 1.3.5 signer diagnostic: app runtime=\(oldMain.runtime), app audio entitlement=\(oldMain.audio), helper runtime=\(oldHelper.runtime). This diagnostic does not claim metadata preservation.")
        try LocalSigning.signApp(clone, config: config)
        let repairedMain = try inspect(clone)
        let repairedHelper = try inspect(LocalSigning.helperURL(clone))
        try LocalSigning.require(repairedMain.runtime && repairedMain.audio && repairedHelper.runtime,
                                 "The current explicit installer signing policy did not restore required metadata.")
        print("Current installer signing restores runtime and audio entitlement on the same isolated clone.")
    }
    static func publicIdentityDiagnostic(config: LocalSigning.Configuration) throws {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        task.arguments = ["find-identity", "-p", "codesigning", config.keychainPath]
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = pipe
        try task.run()
        let output = pipe.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        // Certificate hashes/labels/status only. Never enumerate or print keys,
        // passwords, receiver credentials, or other keychains' contents.
        print("Local signing identity diagnostic:\n" + String(decoding: output.prefix(4096), as: UTF8.self))
        try LocalSigning.require(task.terminationStatus == 0, "The public identity diagnostic failed.")
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
        guard let identityResult = result, CFGetTypeID(identityResult) == SecIdentityGetTypeID() else {
            throw LocalSigning.Failure(message: "The isolated identity was not found.")
        }
        let identity = unsafeBitCast(identityResult, to: SecIdentity.self)
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
    static func runProbe(_ executable: URL, mode: String, keychain: String, service: String) throws {
        let process = Process()
        process.executableURL = executable
        process.arguments = [mode, keychain, service]
        // Probe output contains only generation labels, synthetic partition
        // identifiers and OSStatus values, never credential values/passwords.
        process.standardOutput = FileHandle.standardOutput
        process.standardError = FileHandle.standardError
        try process.run()
        let deadline = ProcessInfo.processInfo.systemUptime + 30
        while process.isRunning && ProcessInfo.processInfo.systemUptime < deadline { Thread.sleep(forTimeInterval: 0.05) }
        if process.isRunning {
            process.terminate()
            let stopDeadline = ProcessInfo.processInfo.systemUptime + 5
            while process.isRunning && ProcessInfo.processInfo.systemUptime < stopDeadline { Thread.sleep(forTimeInterval: 0.05) }
            if process.isRunning { _ = kill(process.processIdentifier, SIGKILL) }
            throw LocalSigning.Failure(message: "Isolated Keychain probe timed out during \(mode).")
        }
        try LocalSigning.require(process.terminationStatus == 0,
            "Isolated Keychain probe \(executable.lastPathComponent) mode \(mode) failed with exit \(process.terminationStatus).")
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
        let mode = arguments[1]
        if mode.hasPrefix("modern-") {
            // Match Credentials' SecItem APIs, but scope every operation to the
            // disposable keychain; never query or mutate the user's credentials.
            let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service, kSecAttrAccount as String: "receiver",
                kSecMatchSearchList as String: [chain]]
            let updated = Data("local-signing-updated".utf8)
            let status: OSStatus
            switch mode {
            case "modern-acl":
                var referenceQuery = query
                referenceQuery[kSecReturnRef as String] = true
                referenceQuery[kSecMatchLimit as String] = kSecMatchLimitOne
                var result: CFTypeRef?
                let found = SecItemCopyMatching(referenceQuery as CFDictionary, &result)
                guard found == errSecSuccess, let item = result,
                      CFGetTypeID(item) == SecKeychainItemGetTypeID() else {
                    fputs("probe ACL reference OSStatus \(found)\n", stderr); exit(6)
                }
                var access: SecAccess?
                let accessStatus = SecKeychainItemCopyAccess(unsafeBitCast(item, to: SecKeychainItem.self), &access)
                guard accessStatus == errSecSuccess, let aclAccess = access else {
                    fputs("probe copy ACL OSStatus \(accessStatus)\n", stderr); exit(6)
                }
                let partitions = SecAccessCopyMatchingACLList(aclAccess, kSecACLAuthorizationPartitionID) as? [SecACL] ?? []
                print("probe isolated item partition ACL count = \(partitions.count)")
                guard !partitions.isEmpty else {
                    fputs("Fixture lacks required partition ACL; continuity result would be inconclusive.\n", stderr); exit(6)
                }
                for acl in partitions {
                    var applications: CFArray?
                    var description: CFString?
                    var prompt = SecKeychainPromptSelector(rawValue: 0)
                    let copied = SecACLCopyContents(acl, &applications, &description, &prompt)
                    guard copied == errSecSuccess else {
                        fputs("probe partition ACL contents OSStatus \(copied)\n", stderr); exit(6)
                    }
                    // Only this disposable item's public partition identifiers;
                    // never print its stored credential data or a real keychain.
                    print("probe isolated partition description = \(String(description as String? ?? "<none>").prefix(4096))")
                }
                exit(0)
            case "modern-add":
                var add = query
                add.removeValue(forKey: kSecMatchSearchList as String)
                add[kSecUseKeychain as String] = chain
                add[kSecValueData as String] = Data(value.utf8)
                add[kSecAttrLabel as String] = "Stan Mic Bridge isolated credential test"
                status = SecItemAdd(add as CFDictionary, nil)
            case "modern-update":
                status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: updated] as CFDictionary)
            case "modern-read", "modern-read-updated", "modern-read-denied":
                var read = query
                read[kSecReturnData as String] = true
                read[kSecMatchLimit as String] = kSecMatchLimitOne
                var result: CFTypeRef?
                let found = SecItemCopyMatching(read as CFDictionary, &result)
                if found == errSecSuccess {
                    let expected = mode == "modern-read-updated" ? updated : Data(value.utf8)
                    status = (result as? Data) == expected ? errSecSuccess : errSecDecode
                } else {
                    status = found
                }
            default: exit(2)
            }
            if mode.hasSuffix("-denied") {
                // Missing item, malformed query, and decoding failures are not
                // evidence that access control rejected the wrong identity.
                guard status == errSecInteractionNotAllowed || status == errSecAuthFailed else {
                    fputs("probe expected ACL denial, OSStatus \(status)\n", stderr); exit(5)
                }
                print("probe generation \(generation) denied by ACL (\(status))")
            } else {
                guard status == errSecSuccess else { fputs("probe modern OSStatus \(status)\n", stderr); exit(4) }
                print("probe generation \(generation) modern API succeeded")
            }
            exit(0)
        }
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
        if mode == "read-denied" {
            guard status == errSecInteractionNotAllowed || status == errSecAuthFailed else {
                fputs("probe expected legacy ACL denial, OSStatus \(status)\n", stderr); exit(5)
            }
            print("probe generation \(generation) legacy API denied by ACL (\(status))")
        } else {
            guard status == errSecSuccess else { fputs("probe OSStatus \(status)\n", stderr); exit(4) }
            print("probe generation \(generation) succeeded")
        }
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
        try FileManager.default.copyItem(at: second, to: wrong)
        try LocalSigning.run("/usr/bin/codesign", ["--force", "--sign", "-", "--identifier", "com.stan.micbridge.signing-probe", wrong.path])
        let modernService = service + ".modern"
        try runProbe(first, mode: "modern-add", keychain: config.keychainPath, service: modernService)
        try runProbe(first, mode: "modern-acl", keychain: config.keychainPath, service: modernService)
        try runProbe(first, mode: "modern-read", keychain: config.keychainPath, service: modernService)
        try runProbe(second, mode: "modern-read-denied", keychain: config.keychainPath, service: modernService)
        try runProbe(wrong, mode: "modern-read-denied", keychain: config.keychainPath, service: modernService)
        // CI demonstrated that SecItemUpdate can succeed for a caller denied
        // secret reads. This diagnostic asserts read privacy, not write denial;
        // only the creator updates its synthetic item here.
        try runProbe(first, mode: "modern-update", keychain: config.keychainPath, service: modernService)
        try runProbe(first, mode: "modern-read-updated", keychain: config.keychainPath, service: modernService)
        try runProbe(second, mode: "modern-read-denied", keychain: config.keychainPath, service: modernService)
        print("Local signing diagnostic: partition-enforced SecItem credential denies secret reads by a distinct self-signed build despite equal designated requirements; original creator retains read/update access. Write protection is not asserted.")
        // The first fixed-signed installation can inherit a receiver item made
        // by an older ad-hoc build. That item's ACL is separate from the app's
        // current signing identity. A fresh-item test does not cover migration.
        let legacyService = service + ".adhoc-origin"
        try runProbe(wrong, mode: "modern-add", keychain: config.keychainPath, service: legacyService)
        try runProbe(wrong, mode: "modern-acl", keychain: config.keychainPath, service: legacyService)
        try runProbe(wrong, mode: "modern-read", keychain: config.keychainPath, service: legacyService)
        try runProbe(first, mode: "modern-read-denied", keychain: config.keychainPath, service: legacyService)
        try runProbe(second, mode: "modern-read-denied", keychain: config.keychainPath, service: legacyService)
        try runProbe(wrong, mode: "modern-read", keychain: config.keychainPath, service: legacyService)
        print("Local signing: inherited ad-hoc credential denies fixed identity without interaction; original item remains readable by its creator. Always Allow migration is not simulated.")
        try runProbe(first, mode: "write", keychain: config.keychainPath, service: service)
        try runProbe(first, mode: "read", keychain: config.keychainPath, service: service)
        try runProbe(second, mode: "read-denied", keychain: config.keychainPath, service: service)
        try runProbe(wrong, mode: "read-denied", keychain: config.keychainPath, service: service)
        print("Local signing diagnostic: legacy SecKeychain API also denies the next distinct self-signed build under partition enforcement.")
    }
}
