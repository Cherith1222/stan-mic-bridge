import Foundation
import Security
import CryptoKit

// Invoked inside LocalSigningTests' disposable, partition-enforced keychain.
// Child probes compile the production client with compile-time-only isolation.
enum CredentialBrokerTests {
    static func run(root: URL, config: LocalSigning.Configuration, sources: URL, password: String) throws {
        let files = FileManager.default
        let fixture = files.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/StanMicBridge-broker-test-\(UUID().uuidString)")
        try files.createDirectory(at: fixture, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? files.removeItem(at: fixture) }
        let signing = LocalSigning.Context(anchor: fixture, directory: fixture.appendingPathComponent("signing"))
        try LocalSigning.saveConfiguration(config, context: signing)
        let bundled = fixture.appendingPathComponent("bundled-broker")
        let installed = fixture.appendingPathComponent("credentials/v1/StanMicCredentialBroker")
        let client = fixture.appendingPathComponent("client")
        let bootstrap = fixture.appendingPathComponent("client-bootstrap")
        let first = fixture.appendingPathComponent("client-one")
        let second = fixture.appendingPathComponent("client-two")
        let wrong = fixture.appendingPathComponent("client-wrong")
        let swift = fixture.appendingPathComponent("BrokerProbe.swift")
        let common = ["swiftc", "-swift-version", "5", "-O", "-D", "BROKER_TESTING", "-framework", "Security"]
        try LocalSigning.run("/usr/bin/xcrun", common + [sources.appendingPathComponent("CredentialBroker.swift").path,
            sources.appendingPathComponent("CredentialBrokerProtocol.swift").path, "-o", bundled.path], timeout: 120, captureTestDiagnostics: true)
        // Explicit fixture bootstrap signs the initially bundled broker once.
        try LocalSigning.run("/usr/bin/codesign", ["--force", "--sign", "-", bundled.path])
        func compileClient(_ generation: String, destination: URL, pin: String, codeHashes: [String] = []) throws {
            try LocalSigning.require(codeHashes.allSatisfy { !$0.isEmpty && $0.allSatisfy { "0123456789abcdef".contains($0) } },
                                     "Fixture code hashes are not hexadecimal literals.")
            let hashLiteral = "[" + codeHashes.map { "\"" + $0 + "\"" }.joined(separator: ",") + "]"
            try probe.replacingOccurrences(of: "__GENERATION__", with: generation)
                .replacingOccurrences(of: "__PIN__", with: pin)
                .replacingOccurrences(of: "__CODE_HASHES__", with: hashLiteral).write(to: swift, atomically: true, encoding: .utf8)
            try LocalSigning.run("/usr/bin/xcrun", common + [sources.appendingPathComponent("CredentialBrokerClient.swift").path,
                sources.appendingPathComponent("CredentialBrokerProtocol.swift").path,
                sources.appendingPathComponent("LocalSigning.swift").path, swift.path, "-o", destination.path], timeout: 120, captureTestDiagnostics: true)
            try LocalSigning.sign(destination, identifier: "com.stan.micbridge", config: config)
        }
        func activate(_ executable: URL) throws {
            if files.fileExists(atPath: client.path) { try files.removeItem(at: client) }
            try files.copyItem(at: executable, to: client)
        }
        func check(_ executable: URL, _ mode: String) throws {
            print("Credential broker isolated test: running \(mode).")
            try LocalSigning.run(executable.path, [mode, fixture.path, config.keychainPath, client.path], timeout: 40, captureTestDiagnostics: true)
            print("Credential broker isolated test: \(mode) passed.")
        }
        try compileClient("bootstrap-only", destination: bootstrap, pin: "")
        try activate(bootstrap)
        try check(client, "helper-rejected") // Missing sealed pin cannot bootstrap during normal load.
        try LocalSigning.require(!files.fileExists(atPath: installed.path), "Normal load bootstrapped a broker without a sealed pin.")
        try check(client, "prepare")
        let original = try Data(contentsOf: installed)
        let digest = SHA256.hash(data: original)
        let pin = digest.map { String(format: "%02x", $0) }.joined()
        let trustedCodeHashes = try CredentialBrokerClient.codeHashes(installed)
        for (generation, destination) in [("first-build", first), ("second-build", second)] {
            try compileClient(generation, destination: destination, pin: pin, codeHashes: trustedCodeHashes)
        }
        try LocalSigning.require(try Data(contentsOf: first) != Data(contentsOf: second), "Broker probes must be distinct builds.")
        try activate(first)
        // Exercise migration before any v2 item exists. The test coordinator is
        // deliberately not an owner of the broker-created item and must not
        // reset/delete it to arrange a later fixture.
        try seedLegacy(installed: installed, config: config, password: password)
        try check(client, "load")
        let chain = try LocalSigning.openKeychain(config.keychainPath)
        let legacyReferenceQuery: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.stan.micbridge", kSecAttrAccount as String: "receiver",
            kSecMatchSearchList as String: [chain], kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne]
        var retainedLegacy: CFTypeRef?
        try LocalSigning.check(SecItemCopyMatching(legacyReferenceQuery as CFDictionary, &retainedLegacy),
                               "Verify migration retained the isolated legacy item")
        try check(client, "save")
        try assertPartition(config: config)
        try check(client, "load")
        try activate(second)
        try check(client, "load")
        try check(client, "save-updated")
        try activate(first)
        try check(client, "load-updated")
        try LocalSigning.require(SHA256.hash(data: try Data(contentsOf: installed)) == digest,
                                 "An app generation changed the installed credential broker.")
        // Same leaf and identifier, but an executable outside the allowed path.
        try check(second, "raw-wrong-path")
        try files.copyItem(at: first, to: wrong)
        try LocalSigning.run("/usr/bin/codesign", ["--force", "--sign", "-", "--options", "runtime", "--identifier", "com.stan.micbridge", wrong.path])
        try activate(wrong)
        try check(client, "raw-wrong-signer")
        try LocalSigning.sign(wrong, identifier: "com.stan.micbridge.other", config: config)
        try activate(wrong)
        try check(client, "raw-wrong-identifier")
        try activate(first)
        try check(client, "raw-malformed")
        try check(client, "raw-oversize")
        try check(client, "load-updated")
        // Fail closed with a missing or modified frozen helper, without reinstall.
        try files.removeItem(at: installed)
        try check(client, "helper-rejected")
        try original.write(to: installed)
        try files.setAttributes([.posixPermissions: 0o700], ofItemAtPath: installed.path)
        var modified = original; modified.append(0)
        try modified.write(to: installed)
        try check(client, "helper-rejected")
        try original.write(to: installed)
        try check(client, "load-updated")
        // A writable sidecar is not a trust anchor. Replace BOTH helper and its
        // manifest with a valid same-certificate/identifier executable. The real
        // client remains byte-for-byte unchanged, with the original compiled pin.
        let forgedSource = fixture.appendingPathComponent("ForgedBroker.swift")
        let forged = fixture.appendingPathComponent("forged-broker")
        try """
        import Foundation
        @main struct ForgedBroker {
            static func main() {
                try? Data("executed".utf8).write(to: URL(fileURLWithPath: CommandLine.arguments[0] + ".executed"))
            }
        }
        """.write(to: forgedSource, atomically: true, encoding: .utf8)
        try LocalSigning.run("/usr/bin/xcrun", common + ["-parse-as-library", forgedSource.path, "-o", forged.path],
                             timeout: 120, captureTestDiagnostics: true)
        try LocalSigning.sign(forged, identifier: "com.stan.micbridge.credentials", config: config)
        let manifestURL = installed.deletingLastPathComponent().appendingPathComponent("manifest.json")
        let manifestBytes = try Data(contentsOf: manifestURL)
        guard var forgedManifest = try JSONSerialization.jsonObject(with: manifestBytes) as? [String: Any] else {
            throw LocalSigning.Failure(message: "Fixture broker manifest is not an object.")
        }
        let forgedBytes = try Data(contentsOf: forged)
        forgedManifest["sha256"] = SHA256.hash(data: forgedBytes).map { String(format: "%02x", $0) }.joined()
        let unchangedClient = try Data(contentsOf: client)
        try forgedBytes.write(to: installed)
        try JSONSerialization.data(withJSONObject: forgedManifest).write(to: manifestURL)
        try check(client, "helper-rejected")
        try LocalSigning.require(!files.fileExists(atPath: installed.path + ".executed"),
                                 "The same-signer replacement helper executed before pin rejection.")
        try LocalSigning.require(try Data(contentsOf: client) == unchangedClient,
                                 "The replacement-helper test changed its trusted client fixture.")
        try original.write(to: installed)
        try manifestBytes.write(to: manifestURL)
        try check(client, "load-updated")
        try check(client, "remove")
        // Reintroduce a legacy value after successful removal: the v2 tombstone
        // must take precedence, so a retained old credential cannot resurrect.
        try seedLegacy(installed: installed, config: config, password: password)
        try check(client, "removed")
        try activate(second)
        try check(client, "removed")
        // Removal blocks implicit legacy resurrection, but an explicit new save
        // must be able to replace the tombstone and survive another app build.
        try check(client, "save-updated")
        try check(client, "load-updated")
        try activate(first)
        try check(client, "load-updated")
        try LocalSigning.require(SHA256.hash(data: try Data(contentsOf: installed)) == digest,
                                 "Credential tests changed the immutable broker.")
        print("Credential broker: two distinct app builds used the same frozen executable; scoped Keychain reads, caller denial, malformed input, migration, tombstone and helper integrity checks passed.")
    }

    static func assertPartition(config: LocalSigning.Configuration) throws {
        let chain = try LocalSigning.openKeychain(config.keychainPath)
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.stan.micbridge.credentials.v2", kSecAttrAccount as String: "receiver",
            kSecMatchSearchList as String: [chain], kSecReturnRef as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var result: CFTypeRef?
        try LocalSigning.check(SecItemCopyMatching(query as CFDictionary, &result), "Inspect isolated broker item reference")
        guard let item = result, CFGetTypeID(item) == SecKeychainItemGetTypeID() else {
            throw LocalSigning.Failure(message: "Isolated broker item reference unavailable.")
        }
        var access: SecAccess?
        try LocalSigning.check(SecKeychainItemCopyAccess(unsafeBitCast(item, to: SecKeychainItem.self), &access), "Inspect isolated broker ACL")
        guard let acl = access, let partitions = SecAccessCopyMatchingACLList(acl, kSecACLAuthorizationPartitionID) as? [SecACL], !partitions.isEmpty else {
            throw LocalSigning.Failure(message: "Broker fixture lacks partition enforcement; test is inconclusive.")
        }
    }

    static func seedLegacy(installed: URL, config: LocalSigning.Configuration, password: String) throws {
        var code: SecStaticCode?
        try LocalSigning.check(SecStaticCodeCreateWithPath(installed as CFURL, [], &code), "Inspect isolated broker signature")
        guard let broker = code else { throw LocalSigning.Failure(message: "Missing isolated broker signature.") }
        var result: CFDictionary?
        try LocalSigning.check(SecCodeCopySigningInformation(broker, SecCSFlags(rawValue: kSecCSSigningInformation), &result), "Inspect isolated broker partition")
        guard let info = result as? [String: Any], let hash = info[kSecCodeInfoUnique as String] as? Data else {
            throw LocalSigning.Failure(message: "Isolated broker code hash unavailable.")
        }
        let partition = "cdhash:" + hash.map { String(format: "%02x", $0) }.joined()
        let synthetic = #"{"origin":"https://fixture.invalid","token":"synthetic-broker-fixture"}"#
        try LocalSigning.run("/usr/bin/security", ["add-generic-password", "-U", "-a", "receiver", "-s", "com.stan.micbridge",
            "-w", synthetic, "-T", installed.path, config.keychainPath])
        try LocalSigning.run("/usr/bin/security", ["set-generic-password-partition-list", "-a", "receiver", "-s", "com.stan.micbridge",
            "-S", partition, "-k", password, config.keychainPath])
    }

    static let probe = #"""
    import Foundation
    import Security
    import Darwin
    @main struct BrokerProbe {
        static func main() {
            signal(SIGPIPE, SIG_IGN)
            SecKeychainSetUserInteractionAllowed(false)
            do { try run() } catch {
                // Type/code only: no request, credential bytes or argv logging.
                fputs("Broker synthetic probe __GENERATION__ failed: \(String(reflecting: type(of: error))), code \((error as NSError).code).\n", stderr)
                if let failure = error as? CredentialBrokerClient.Failure,
                   let range = failure.message.range(of: "-[0-9]{4,8}", options: .regularExpression) {
                    fputs("Broker synthetic OSStatus \(failure.message[range]).\n", stderr)
                }
                exit(1)
            }
        }
        static func run() throws {
            let args = CommandLine.arguments
            guard args.count == 5 else { exit(2) }
            let mode = args[1], root = URL(fileURLWithPath: args[2])
            let app = URL(fileURLWithPath: args[0]).standardizedFileURL
            let signing = LocalSigning.Context(anchor: root, directory: root.appendingPathComponent("signing"))
            let context = CredentialBrokerClient.Context(anchor: root, directory: root.appendingPathComponent("credentials"),
                appURL: app, bundledBrokerURL: root.appendingPathComponent("bundled-broker"), signingContext: signing,
                testKeychain: args[3], testExpectedParentPath: args[4], testPinnedSHA256: "__PIN__".isEmpty ? nil : "__PIN__",
                testPinnedCodeHashes: __CODE_HASHES__)
            let value = Data(#"{"origin":"https://fixture.invalid","token":"synthetic-broker-fixture"}"#.utf8)
            let updated = Data(#"{"origin":"https://fixture.invalid","token":"synthetic-updated-fixture"}"#.utf8)
            if mode.hasPrefix("raw-") {
                try raw(root: root, mode: mode, keychain: args[3], expected: args[4]); return
            }
            switch mode {
            case "prepare": _ = try CredentialBrokerClient.bootstrapForTests(context: context)
            case "save": _ = try CredentialBrokerClient.perform("save", payload: value, context: context)
            case "save-updated": _ = try CredentialBrokerClient.perform("save", payload: updated, context: context)
            case "load", "load-updated":
                let received = try CredentialBrokerClient.perform("load", context: context)
                try LocalSigning.require(received == (mode == "load" ? value : updated), "Synthetic value mismatch.")
            case "remove": _ = try CredentialBrokerClient.perform("remove", context: context)
            case "removed":
                try LocalSigning.require(try CredentialBrokerClient.perform("load", context: context) == nil, "Tombstone revived a legacy fixture.")
            case "helper-rejected":
                var denied = false
                do { _ = try CredentialBrokerClient.perform("load", context: context) } catch { denied = true }
                try LocalSigning.require(denied, "Missing or tampered helper was accepted.")
            default: exit(2)
            }
        }
        static func raw(root: URL, mode: String, keychain: String, expected: String) throws {
            let task = Process(), input = Pipe(), output = Pipe()
            task.executableURL = root.appendingPathComponent("credentials/v1/StanMicCredentialBroker")
            task.arguments = []
            task.environment = ["BROKER_TEST_EXPECTED_PARENT_PATH": expected]
            task.standardInput = input; task.standardOutput = output; task.standardError = FileHandle.nullDevice
            try task.run()
            let rejectedCaller = mode.hasPrefix("raw-wrong-")
            let bytes: Data
            if mode == "raw-oversize" { bytes = Data(repeating: 0x78, count: 16385) }
            else if mode == "raw-malformed" { bytes = Data("{invalid".utf8) }
            else { bytes = try JSONSerialization.data(withJSONObject: ["schema": 1, "operation": "load", "testKeychain": keychain]) }
            // No real secret is involved. Raw negative probes deliberately test
            // the helper boundary independently of client preflight validation.
            try? input.fileHandleForWriting.write(contentsOf: bytes)
            try? input.fileHandleForWriting.close()
            let deadline = ProcessInfo.processInfo.systemUptime + 20
            while task.isRunning && ProcessInfo.processInfo.systemUptime < deadline { Thread.sleep(forTimeInterval: 0.02) }
            if task.isRunning { task.terminate(); _ = kill(task.processIdentifier, SIGKILL); throw LocalSigning.Failure(message: "Raw probe timed out.") }
            let received = output.fileHandleForReading.readDataToEndOfFile()
            try LocalSigning.require(task.terminationStatus == (rejectedCaller ? 77 : 65), "Unexpected raw rejection status.")
            if rejectedCaller { try LocalSigning.require(received.isEmpty, "Unauthorized caller received broker data.") }
            else {
                let ready = try JSONDecoder().decode(CredentialBrokerWire.Response.self, from: received)
                try LocalSigning.require(ready.schema == 1 && ready.status == 0 && ready.data == nil, "Malformed request returned data.")
            }
        }
    }
    """#
}
