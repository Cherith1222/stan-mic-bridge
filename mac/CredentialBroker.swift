import Foundation
import Security
import CryptoKit
import Darwin

// Installed once with a fixed signature; app updates keep these executable bytes.
// One authenticated direct parent, one anonymous-pipe request, then exit. No logs.
@main
struct CredentialBroker {
    enum Failure: Error { case unauthorized, invalid }
    static let service = "com.stan.micbridge.credentials.v2"
    static let legacyService = "com.stan.micbridge"
    static let account = "receiver"

    struct Caller {
        let pid: pid_t
        let requirement: SecRequirement
        let expectedExecutable: String
        let home: String
        init() throws {
            guard let entry = getpwuid(geteuid()), let directory = entry.pointee.pw_dir,
                  let resolved = realpath(directory, nil) else { throw Failure.unauthorized }
            home = String(cString: resolved)
            free(resolved)
            #if BROKER_TESTING
            guard let testExecutable = ProcessInfo.processInfo.environment["BROKER_TEST_EXPECTED_PARENT_PATH"],
                  testExecutable.hasPrefix(home + "/") else { throw Failure.unauthorized }
            expectedExecutable = testExecutable
            #else
            expectedExecutable = home + "/Applications/Stan Mic Bridge.app/Contents/MacOS/StanMicBridge"
            #endif
            pid = getppid()
            guard pid > 1 else { throw Failure.unauthorized }
            var own: SecCode?
            guard SecCodeCopySelf([], &own) == errSecSuccess, let code = own,
                  SecCodeCheckValidity(code, [], nil) == errSecSuccess else { throw Failure.unauthorized }
            var staticCode: SecStaticCode?
            guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let ownStatic = staticCode else {
                throw Failure.unauthorized
            }
            var information: CFDictionary?
            guard SecCodeCopySigningInformation(ownStatic, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
                  let info = information as? [String: Any], Self.hardened(info, allowAudio: false),
                  info[kSecCodeInfoIdentifier as String] as? String == CredentialBrokerWire.brokerIdentifier,
                  let certificates = info[kSecCodeInfoCertificates as String] as? [SecCertificate],
                  let leaf = certificates.first else { throw Failure.unauthorized }
            let fingerprint = Insecure.SHA1.hash(data: SecCertificateCopyData(leaf) as Data).map { String(format: "%02x", $0) }.joined()
            var parsed: SecRequirement?
            let expression = "identifier \"\(CredentialBrokerWire.appIdentifier)\" and certificate leaf = H\"\(fingerprint)\""
            guard SecRequirementCreateWithString(expression as CFString, [], &parsed) == errSecSuccess,
                  let required = parsed else { throw Failure.unauthorized }
            requirement = required
            try validate()
        }
        static func hardened(_ info: [String: Any], allowAudio: Bool) -> Bool {
            guard let flags = info[kSecCodeInfoFlags as String] as? NSNumber,
                  flags.uint32Value & 0x10000 != 0 else { return false } // kSecCodeSignatureRuntime
            let entitlements = info[kSecCodeInfoEntitlementsDict as String] as? [String: Any] ?? [:]
            let allowed: Set<String> = allowAudio ? ["com.apple.security.device.audio-input"] : []
            // No debugger, injected-library, unsigned executable memory or JIT
            // exceptions. The app's microphone entitlement does not weaken IPC.
            return Set(entitlements.keys).isSubset(of: allowed)
        }
        func validate() throws {
            guard getppid() == pid else { throw Failure.unauthorized }
            var guest: SecCode?
            let attributes = [kSecGuestAttributePid as String: NSNumber(value: pid)] as CFDictionary
            guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &guest) == errSecSuccess,
                  let parent = guest, SecCodeCheckValidity(parent, [], requirement) == errSecSuccess,
                  getppid() == pid else { throw Failure.unauthorized }
            var parentStatic: SecStaticCode?
            guard SecCodeCopyStaticCode(parent, [], &parentStatic) == errSecSuccess, let executableCode = parentStatic else {
                throw Failure.unauthorized
            }
            var information: CFDictionary?
            guard SecCodeCopySigningInformation(executableCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
                  let info = information as? [String: Any], Self.hardened(info, allowAudio: true),
                  let executable = info[kSecCodeInfoMainExecutable as String] as? URL,
                  executable.path == expectedExecutable else { throw Failure.unauthorized }
            let suffix = expectedExecutable.dropFirst(home.count + 1)
            let components = suffix.split(separator: "/", omittingEmptySubsequences: false)
            guard !components.isEmpty, components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
                throw Failure.unauthorized
            }
            var current = home
            for (index, component) in components.enumerated() {
                current += "/" + component
                var metadata = stat()
                let kind = index == components.count - 1 ? mode_t(S_IFREG) : mode_t(S_IFDIR)
                guard lstat(current, &metadata) == 0, metadata.st_mode & mode_t(S_IFMT) == kind,
                      metadata.st_uid == geteuid(), metadata.st_mode & 0o022 == 0 else { throw Failure.unauthorized }
            }
            guard getppid() == pid, SecCodeCheckValidity(parent, [], requirement) == errSecSuccess else {
                throw Failure.unauthorized
            }
        }
    }

    struct Store {
        let caller: Caller
        #if BROKER_TESTING
        let keychain: SecKeychain
        #endif
        init(caller: Caller, request: CredentialBrokerWire.Request) throws {
            self.caller = caller
            #if BROKER_TESTING
            // Available only in the separate CI executable, never production.
            guard let path = request.testKeychain,
                  URL(fileURLWithPath: path).lastPathComponent.hasPrefix("StanMicBridge-"),
                  URL(fileURLWithPath: path).deletingLastPathComponent().standardizedFileURL ==
                    URL(fileURLWithPath: caller.home).appendingPathComponent("Library/Keychains").standardizedFileURL else {
                throw Failure.invalid
            }
            var metadata = stat()
            guard lstat(path, &metadata) == 0, metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
                  metadata.st_uid == geteuid() else { throw Failure.invalid }
            var opened: SecKeychain?
            guard SecKeychainOpen(path, &opened) == errSecSuccess, let chain = opened else { throw Failure.invalid }
            keychain = chain
            SecKeychainSetUserInteractionAllowed(false)
            #endif
        }
        func query(_ service: String, adding: Bool = false) -> [String: Any] {
            var result: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service, kSecAttrAccount as String: CredentialBroker.account]
            #if BROKER_TESTING
            if adding { result[kSecUseKeychain as String] = keychain }
            else { result[kSecMatchSearchList as String] = [keychain] }
            #endif
            return result
        }
        func read(_ service: String) throws -> (OSStatus, Data?) {
            try caller.validate()
            var search = query(service)
            search[kSecReturnData as String] = true
            search[kSecMatchLimit as String] = kSecMatchLimitOne
            var result: CFTypeRef?
            let status = SecItemCopyMatching(search as CFDictionary, &result)
            try caller.validate()
            guard status == errSecSuccess else { return (status, nil) }
            guard let bytes = result as? Data else { return (errSecDecode, nil) }
            return (errSecSuccess, bytes)
        }
        func write(_ data: Data) throws -> OSStatus {
            try caller.validate()
            var status = SecItemUpdate(query(CredentialBroker.service) as CFDictionary, [kSecValueData as String: data] as CFDictionary)
            if status == errSecItemNotFound {
                try caller.validate()
                var add = query(CredentialBroker.service, adding: true)
                add[kSecValueData as String] = data
                add[kSecAttrLabel as String] = "Stan Mic Bridge receiver"
                status = SecItemAdd(add as CFDictionary, nil)
            }
            try caller.validate()
            guard status == errSecSuccess else { return status }
            let verification = try read(CredentialBroker.service)
            guard verification.0 == errSecSuccess else { return verification.0 }
            return verification.1 == data ? errSecSuccess : errSecDecode
        }
        func load() throws -> (OSStatus, Data?) {
            let current = try read(CredentialBroker.service)
            if current.0 == errSecSuccess {
                guard let data = current.1 else { return (errSecDecode, nil) }
                // Tombstone means removed; never revive the retained legacy copy.
                if data.isEmpty { return (errSecItemNotFound, nil) }
                return CredentialBrokerWire.ConnectionData.decode(data) != nil ? current : (errSecDecode, nil)
            }
            guard current.0 == errSecItemNotFound else { return current }
            let old = try read(CredentialBroker.legacyService)
            guard old.0 == errSecSuccess, let data = old.1 else { return old }
            guard CredentialBrokerWire.ConnectionData.decode(data) != nil else { return (errSecDecode, nil) }
            // Add-only migration cannot overwrite an item created concurrently.
            try caller.validate()
            var add = query(CredentialBroker.service, adding: true)
            add[kSecValueData as String] = data
            add[kSecAttrLabel as String] = "Stan Mic Bridge receiver"
            let added = SecItemAdd(add as CFDictionary, nil)
            guard added == errSecSuccess else { return (added, nil) }
            let verification = try read(CredentialBroker.service)
            guard verification.0 == errSecSuccess else { return verification }
            guard verification.1 == data else { return (errSecDecode, nil) }
            return verification
        }
        func remove() throws -> OSStatus {
            let tombstone = try write(Data())
            guard tombstone == errSecSuccess else { return tombstone }
            try caller.validate()
            let deleted = SecItemDelete(query(CredentialBroker.legacyService) as CFDictionary)
            try caller.validate()
            return deleted == errSecItemNotFound ? errSecSuccess : deleted
        }
    }

    static func readRequest() throws -> Data {
        var input = Data()
        let deadline = ProcessInfo.processInfo.systemUptime + 15
        while ProcessInfo.processInfo.systemUptime < deadline {
            var descriptor = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN | POLLHUP), revents: 0)
            let ready = poll(&descriptor, 1, 250)
            if ready < 0 { if errno == EINTR { continue }; throw Failure.invalid }
            if ready == 0 { continue }
            var buffer = [UInt8](repeating: 0, count: 4096)
            let count = Darwin.read(STDIN_FILENO, &buffer, 4096)
            if count < 0 { if errno == EINTR { continue }; throw Failure.invalid }
            if count == 0 { return input }
            guard input.count + count <= CredentialBrokerWire.maximumMessageBytes else { throw Failure.invalid }
            input.append(contentsOf: buffer.prefix(count))
        }
        throw Failure.invalid
    }
    static func emit(_ value: CredentialBrokerWire.Response, caller: Caller) throws {
        var response = try JSONEncoder().encode(value)
        guard response.count < CredentialBrokerWire.maximumMessageBytes else { throw Failure.invalid }
        response.append(0x0a)
        try caller.validate()
        try FileHandle.standardOutput.write(contentsOf: response)
    }
    static func main() {
        signal(SIGPIPE, SIG_IGN)
        do {
            guard CommandLine.arguments.count == 1 else { throw Failure.invalid }
            var incoming = stat(), outgoing = stat()
            guard fstat(STDIN_FILENO, &incoming) == 0, fstat(STDOUT_FILENO, &outgoing) == 0,
                  incoming.st_mode & mode_t(S_IFMT) == mode_t(S_IFIFO),
                  outgoing.st_mode & mode_t(S_IFMT) == mode_t(S_IFIFO) else { throw Failure.invalid }
            let caller = try Caller()
            // The app authenticates this live child after ready and before it
            // sends any credential payload, closing the path-check/exec gap.
            try emit(CredentialBrokerWire.Response(schema: 1, status: errSecSuccess, data: nil), caller: caller)
            let bytes = try readRequest()
            try caller.validate()
            guard let request = try? JSONDecoder().decode(CredentialBrokerWire.Request.self, from: bytes), request.isValid else {
                throw Failure.invalid
            }
            let store = try Store(caller: caller, request: request)
            let outcome: (OSStatus, Data?)
            switch request.operation {
            case "load": outcome = try store.load()
            case "save": outcome = (try store.write(request.payload!), nil)
            case "remove": outcome = (try store.remove(), nil)
            default: throw Failure.invalid
            }
            try caller.validate()
            try emit(CredentialBrokerWire.Response(schema: 1, status: outcome.0, data: outcome.1), caller: caller)
        } catch Failure.unauthorized {
            exit(77)
        } catch {
            exit(65)
        }
    }
}
