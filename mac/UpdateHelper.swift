import AppKit
import Foundation
import Darwin

// Independent, short-lived replacement helper. It never asks for elevated privileges.
private enum UpdateError: Error, CustomStringConvertible {
    case message(String)
    var description: String { if case .message(let text) = self { return text }; return "Update failed" }
}
private let files = FileManager.default
private struct ResumeIntent: Codable { let parentPID: Int32; let build: String; let createdAt: Double }
private struct ResumeGrant: Codable { let build: String; let createdAt: Double; let nonce: String }
private func consumeResumeIntent(root: URL, parent: Int32, build: String, now: Double = Date().timeIntervalSince1970) -> Bool {
    let file = root.appendingPathComponent("resume-intent.json")
    guard let attributes = try? files.attributesOfItem(atPath: file.path),
          attributes[.type] as? FileAttributeType == .typeRegular,
          (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == geteuid(),
          (attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600,
          ((attributes[.size] as? NSNumber)?.intValue ?? 99999) <= 4096,
          let data = try? Data(contentsOf: file) else { return false }
    do { try files.removeItem(at: file) } catch { return false }
    guard let intent = try? JSONDecoder().decode(ResumeIntent.self, from: data) else { return false }
    return intent.parentPID == parent && intent.build == build && intent.createdAt.isFinite
        && intent.createdAt <= now + 5 && now - intent.createdAt <= 600
}
private func createResumeGrant(root: URL, build: String) throws -> String {
    let nonce = (UUID().uuidString + UUID().uuidString).replacingOccurrences(of: "-", with: "").lowercased()
    let file = root.appendingPathComponent("resume-once.json")
    try require((try? files.attributesOfItem(atPath: file.path)) == nil, "An update resume grant already exists.")
    let data = try JSONEncoder().encode(ResumeGrant(build: build, createdAt: Date().timeIntervalSince1970, nonce: nonce))
    try data.write(to: file, options: .atomic)
    try files.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
    return nonce
}
private func require(_ condition: Bool, _ message: String) throws {
    if !condition { throw UpdateError.message(message) }
}
private func run(_ executable: String, _ arguments: [String]) throws {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: executable)
    task.arguments = arguments
    task.standardOutput = FileHandle.nullDevice
    task.standardError = FileHandle.nullDevice
    try task.run()
    task.waitUntilExit()
    try require(task.terminationStatus == 0, "Validation or launch failed (\(URL(fileURLWithPath: executable).lastPathComponent)).")
}
// Retained solely to reproduce the historical Foundation alias bug in CI.
private func legacyNoSymlinks(_ path: URL) throws {
    var current = path.standardizedFileURL
    while current.path != "/" {
        let attributes = try files.attributesOfItem(atPath: current.path)
        try require(attributes[.type] as? FileAttributeType != .typeSymbolicLink, "A symbolic link was found in the installation path: \(current.path)")
        current.deleteLastPathComponent()
    }
}
private func canonicalAnchor(_ anchor: URL) throws -> URL {
    guard let resolved = realpath(anchor.path, nil) else {
        throw UpdateError.message("The trusted update directory is unavailable: \(anchor.path)")
    }
    defer { free(resolved) }
    return URL(fileURLWithPath: String(cString: resolved), isDirectory: true)
}
// Repeated separators are harmless POSIX spelling (TMPDIR commonly ends in '/').
// Reject traversal tokens before constructing a URL or doing any normalization.
private func normalizedSeparators(_ path: String) throws -> String {
    try require(path.hasPrefix("/"), "The app path must be absolute.")
    let components = path.split(separator: "/", omittingEmptySubsequences: true)
    try require(components.allSatisfy { $0 != "." && $0 != ".." },
                "The app path contains an invalid path component.")
    return "/" + components.joined(separator: "/")
}
// Only the OS-provided anchor may contain aliases such as /var -> /private/var.
// Never resolve the candidate: that would hide a link in Applications or staging.
private func noSymlinksUnderAnchor(_ candidate: URL, anchor: URL) throws -> URL {
    let canonical = try canonicalAnchor(anchor)
    let canonicalPath = try normalizedSeparators(canonical.path)
    let rawAnchor = try normalizedSeparators(anchor.path)
    let candidatePath = try normalizedSeparators(candidate.path)
    let spellings = [canonicalPath, rawAnchor].sorted { $0.count > $1.count }
    guard let matched = spellings.first(where: { candidatePath.hasPrefix($0 + "/") }) else {
        throw UpdateError.message("The app path is outside its trusted update directory.")
    }
    let components = candidatePath.dropFirst(matched.count + 1).split(separator: "/", omittingEmptySubsequences: false)
    try require(!components.isEmpty && components.allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." },
                "The app path contains an invalid path component.")
    var current = canonicalPath
    for (index, component) in components.enumerated() {
        current += "/" + String(component)
        var metadata = stat()
        try require(lstat(current, &metadata) == 0, "An update path component is unavailable: \(current)")
        let type = metadata.st_mode & mode_t(S_IFMT)
        try require(type != mode_t(S_IFLNK), "A symbolic link was found below the trusted update directory: \(current)")
        if index < components.count - 1 {
            try require(type == mode_t(S_IFDIR), "An update path component is not a directory: \(current)")
        }
    }
    return URL(fileURLWithPath: current)
}
private struct InstallationPaths {
    let destination: URL
    let staged: URL
    let stagingRoot: URL
    let temporary: URL
}
// Production and path-regression tests use the same preflight. Tests supply
// private fixture anchors; install() always supplies OS home and temp anchors.
private func installationPaths(destination: URL, staged: URL, home: URL, temporary: URL) throws -> InstallationPaths {
    let checkedDestination = try noSymlinksUnderAnchor(destination, anchor: home)
    let expected = try canonicalAnchor(home).appendingPathComponent("Applications/Stan Mic Bridge.app")
    try require(checkedDestination.path == expected.path, "This updater only supports ~/Applications/Stan Mic Bridge.app.")
    let checkedStage = try noSymlinksUnderAnchor(staged, anchor: temporary)
    let checkedTemporary = try canonicalAnchor(temporary)
    let expanded = checkedStage.deletingLastPathComponent()
    let stagingRoot = expanded.deletingLastPathComponent()
    let prefix = "StanMicBridge-update-"
    try require(checkedStage.lastPathComponent == "Stan Mic Bridge.app"
        && expanded.lastPathComponent == "expanded"
        && stagingRoot.deletingLastPathComponent().path == checkedTemporary.path
        && stagingRoot.lastPathComponent.hasPrefix(prefix)
        && UUID(uuidString: String(stagingRoot.lastPathComponent.dropFirst(prefix.count))) != nil,
        "The updater staging directory has an unexpected layout.")
    let attributes = try files.attributesOfItem(atPath: stagingRoot.path)
    let owner = (attributes[.ownerAccountID] as? NSNumber)?.uint32Value
    let mode = (attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0o777
    try require(owner == geteuid() && mode & 0o077 == 0, "The update staging directory must be private to the current user.")
    return InstallationPaths(destination: checkedDestination, staged: checkedStage,
                             stagingRoot: stagingRoot, temporary: checkedTemporary)
}
private func testPaths(builtApp: URL? = nil) throws {
    let temporary = files.temporaryDirectory
    let fixture = temporary.appendingPathComponent("StanMicUpdater-path-test-\(UUID().uuidString)")
    try files.createDirectory(at: fixture, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? files.removeItem(at: fixture) }
    print("Temporary anchor: \(temporary.path)")
    print("Resolved anchor: \(temporary.resolvingSymlinksInPath().path)")
    print("Standardized resolved anchor: \(temporary.resolvingSymlinksInPath().standardizedFileURL.path)")
    print("Home anchor: \(files.homeDirectoryForCurrentUser.path)")
    do {
        try legacyNoSymlinks(fixture.resolvingSymlinksInPath())
        print("Legacy full-ancestor check accepted the real temporary fixture.")
    } catch {
        print("LEGACY PATH REPRODUCTION: \(error)")
    }
    let home = fixture.appendingPathComponent("home")
    let destination = home.appendingPathComponent("Applications/Stan Mic Bridge.app")
    let stagingRoot = temporary.appendingPathComponent("StanMicBridge-update-\(UUID().uuidString)")
    try files.createDirectory(at: stagingRoot, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? files.removeItem(at: stagingRoot) }
    let staged = stagingRoot.appendingPathComponent("expanded/Stan Mic Bridge.app")
    try files.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
    try files.createDirectory(at: staged.deletingLastPathComponent(), withIntermediateDirectories: true)
    if let app = builtApp {
        try verify(app)
        try files.copyItem(at: app, to: destination)
        try files.copyItem(at: app, to: staged)
        let infoPath = destination.appendingPathComponent("Contents/Info.plist")
        let data = try Data(contentsOf: infoPath)
        guard var info = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] else {
            throw UpdateError.message("The test app has no Info.plist dictionary.")
        }
        let newBuild = try bundleBuild(app)
        try require(newBuild > 1, "The install-path fixture needs a build greater than 1.")
        info["CFBundleVersion"] = String(newBuild - 1)
        try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: infoPath)
        try run("/usr/bin/codesign", ["--force", "--sign", "-", destination.path])
    } else {
        try files.createDirectory(at: destination, withIntermediateDirectories: false)
        try files.createDirectory(at: staged, withIntermediateDirectories: false)
    }
    let checked = try installationPaths(destination: destination, staged: staged, home: home, temporary: temporary)
    let checkedAgain = try installationPaths(destination: checked.destination, staged: checked.staged,
                                             home: home, temporary: temporary)
    try require(checked.destination.path == checkedAgain.destination.path && checked.staged.path == checkedAgain.staged.path,
                "Raw and canonical anchor spellings disagree.")
    print("Production install preflight accepted raw and canonical trusted-anchor spellings.")
    // Every untrusted descendant must remain a real directory, including a link
    // whose target stays inside the anchor (not only links that escape it).
    let attacks = [destination.deletingLastPathComponent(), destination, stagingRoot,
                   staged.deletingLastPathComponent(), staged]
    for original in attacks {
        let saved = original.deletingLastPathComponent().appendingPathComponent("saved-\(UUID().uuidString)")
        try files.moveItem(at: original, to: saved)
        do {
            try files.createSymbolicLink(at: original, withDestinationURL: saved)
            var rejected = false
            do { _ = try installationPaths(destination: destination, staged: staged, home: home, temporary: temporary) }
            catch { rejected = String(describing: error).contains("symbolic link") }
            try files.removeItem(at: original)
            try files.moveItem(at: saved, to: original)
            try require(rejected, "A descendant symbolic link was not rejected: \(original.lastPathComponent)")
            print("Rejected descendant link: \(original.lastPathComponent)")
        } catch {
            if let attributes = try? files.attributesOfItem(atPath: original.path),
               attributes[.type] as? FileAttributeType == .typeSymbolicLink {
                try? files.removeItem(at: original)
            }
            if !files.fileExists(atPath: original.path) { try? files.moveItem(at: saved, to: original) }
            throw error
        }
    }
    if builtApp != nil {
        let paths = try installationPaths(destination: destination, staged: staged, home: home, temporary: temporary)
        try verify(paths.destination)
        try verify(paths.staged)
        let newBuild = try bundleBuild(paths.staged)
        try require(newBuild > bundleBuild(paths.destination), "The test replacement is not newer.")
        let incoming = paths.destination.deletingLastPathComponent().appendingPathComponent(".incoming-test.app")
        let backup = paths.destination.deletingLastPathComponent().appendingPathComponent("backup-test.app")
        try files.copyItem(at: paths.staged, to: incoming)
        try verify(incoming)
        try replace(destination: paths.destination, incoming: incoming, backup: backup,
            move: { try files.moveItem(at: $0, to: $1) }, launch: { app in
                try verify(app)
                try require(try bundleBuild(app) == newBuild, "Replacement build did not match.")
                try testStartup(app.path)
            }, exists: { files.fileExists(atPath: $0.path) })
        try verify(backup)
        print("Signed app install preflight, copy, backup, replacement and real startup passed.")
    }
}
private func bundleBuild(_ app: URL) throws -> Int {
    let data = try Data(contentsOf: app.appendingPathComponent("Contents/Info.plist"))
    let object = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
    guard let info = object as? [String: Any],
          info["CFBundleIdentifier"] as? String == "com.stan.micbridge",
          info["CFBundleExecutable"] as? String == "StanMicBridge",
          let buildText = info["CFBundleVersion"] as? String,
          let build = Int(buildText), build > 0 else {
        throw UpdateError.message("The app bundle has an unexpected identity or build number.")
    }
    return build
}
private func verify(_ app: URL) throws {
    _ = try bundleBuild(app)
    try run("/usr/bin/codesign", ["--verify", "--deep", "--strict", app.path])
}

// All callbacks are injected for tests; rollback restores the original bundle on
// either replacement or launch failure. Backups are deliberately never deleted.
private func replace(destination: URL, incoming: URL, backup: URL,
                     move: (URL, URL) throws -> Void,
                     launch: (URL) throws -> Void,
                     beforeRollback: () throws -> Void = {},
                     exists: (URL) -> Bool) throws {
    try move(destination, backup)
    do {
        try move(incoming, destination)
        try launch(destination)
    } catch {
        let originalError = error
        do {
            try beforeRollback()
            if exists(destination) {
                let failed = destination.deletingLastPathComponent()
                    .appendingPathComponent("Stan Mic Bridge-failed-\(UUID().uuidString).app")
                try move(destination, failed)
            }
            try move(backup, destination)
        } catch {
            throw UpdateError.message("Update failed and automatic restoration could not finish: \(error) Your original app is preserved at \(backup.path). After quitting the app, move the backup back to \(destination.path).")
        }
        throw UpdateError.message("Update failed. Your original app was restored: \(originalError)")
    }
}
private struct ReadyReceipt: Decodable {
    let pid: Int32
    let build: String
    let resumeGrantConsumed: Bool?
}
private func waitForReadiness(receipt: URL, build: String, timeout: TimeInterval = 30,
                              alive: (Int32) -> Bool) throws {
    let deadline = ProcessInfo.processInfo.systemUptime + timeout
    while true {
        if let data = try? Data(contentsOf: receipt),
           let ready = try? JSONDecoder().decode(ReadyReceipt.self, from: data),
           ready.build == build, ready.pid > 1, alive(ready.pid) {
            Thread.sleep(forTimeInterval: 0.5)
            try require(alive(ready.pid), "The new app exited immediately after starting.")
            return
        }
        try require(ProcessInfo.processInfo.systemUptime < deadline,
                    "The new app did not confirm startup in time.")
        Thread.sleep(forTimeInterval: 0.1)
    }
}
private func matchingLaunch(_ app: NSRunningApplication, destination: URL, since: Date) -> Bool {
    guard let bundle = app.bundleURL, let date = app.launchDate else { return false }
    return app.bundleIdentifier == "com.stan.micbridge"
        && sameObservedBundle(bundle, destination)
        && date >= since
}
// These URLs are used only to compare an OS-reported running process with an
// already validated destination. File mutations use installationPaths instead.
private func sameObservedBundle(_ observed: URL, _ destination: URL) -> Bool {
    guard let left = try? canonicalAnchor(observed), let right = try? canonicalAnchor(destination) else { return false }
    return left.path == right.path
}
private func stopFailedLaunch(destination: URL, since: Date) throws {
    let candidates = NSRunningApplication.runningApplications(withBundleIdentifier: "com.stan.micbridge")
        .filter { matchingLaunch($0, destination: destination, since: since) }
    var refusedTermination = false
    for app in candidates where !app.isTerminated {
        if !app.terminate() { refusedTermination = true }
    }
    let deadline = ProcessInfo.processInfo.systemUptime + 10
    while candidates.contains(where: { candidate in
        guard kill(candidate.processIdentifier, 0) == 0,
              let current = NSRunningApplication(processIdentifier: candidate.processIdentifier) else { return false }
        return !current.isTerminated && matchingLaunch(current, destination: destination, since: since)
    }) {
        try require(ProcessInfo.processInfo.systemUptime < deadline,
                    refusedTermination
                        ? "The newly launched app refused normal termination, possibly because a permission or setup dialog is open. Close that dialog and quit the app. The original backup was retained."
                        : "The newly launched app did not finish quitting within 10 seconds. Close any permission or setup dialog and quit the app. The original backup was retained.")
        // NSRunningApplication state changes are delivered through the run loop.
        // Sleeping alone can leave its cached state stale in this command-line helper.
        if !RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.1)) {
            Thread.sleep(forTimeInterval: 0.1)
        }
    }
    // Never move a bundle still used by any app, including a simultaneous manual launch.
    let stillRunning = NSRunningApplication.runningApplications(withBundleIdentifier: "com.stan.micbridge")
        .contains {
            guard let bundle = $0.bundleURL else { return false }
            return sameObservedBundle(bundle, destination) && !$0.isTerminated && kill($0.processIdentifier, 0) == 0
        }
    try require(!stillRunning, "An app is still using the replacement bundle. The original backup was retained.")
}
private func waitForParent(_ pid: pid_t, timeout: TimeInterval = 30) throws {
    let deadline = ProcessInfo.processInfo.systemUptime + timeout
    while true {
        if kill(pid, 0) != 0 {
            if errno == ESRCH { return }
            throw UpdateError.message("Unable to confirm that the running app has exited.")
        }
        try require(ProcessInfo.processInfo.systemUptime < deadline,
                    "The app did not exit in time. No installed files were changed. Quit it and try the update again.")
        Thread.sleep(forTimeInterval: 0.1)
    }
}
private func install(_ arguments: [String]) throws {
    try require(arguments.count == 3, "Invalid updater arguments.")
    guard let parent = Int32(arguments[0]), parent > 1 else { throw UpdateError.message("Invalid app process.") }
    // The app may exit before this process starts; launchd then adopts us.
    // A reused PID can only cause a bounded timeout, never termination.
    try require(getppid() == parent || getppid() == 1, "The updater was not launched by the expected app.")
    try require(arguments[1].hasPrefix("/") && arguments[2].hasPrefix("/"), "Absolute app paths are required.")
    let paths = try installationPaths(destination: URL(fileURLWithPath: normalizedSeparators(arguments[2])),
        staged: URL(fileURLWithPath: normalizedSeparators(arguments[1])), home: files.homeDirectoryForCurrentUser,
        temporary: files.temporaryDirectory)
    let destination = paths.destination
    let resolvedStage = paths.staged
    let temporary = paths.temporary
    let expanded = resolvedStage.deletingLastPathComponent()
    let stagingRoot = paths.stagingRoot
    let prefix = "StanMicBridge-update-"
    let receipt = stagingRoot.appendingPathComponent("update-ready.json")
    try require(!files.fileExists(atPath: receipt.path), "A startup receipt already exists. Please retry the update.")
    try verify(resolvedStage)
    let oldBuild = try bundleBuild(destination)
    let newBuild = try bundleBuild(resolvedStage)
    try require(newBuild > oldBuild, "The downloaded app is not a newer build.")
    // Older helpers ignore this optional intent and launch stopped. Never infer
    // permission to capture from a persisted preference alone.
    let resumeRequested = consumeResumeIntent(root: stagingRoot, parent: parent, build: String(newBuild))
    try waitForParent(parent)
    _ = try installationPaths(destination: destination, staged: resolvedStage,
        home: files.homeDirectoryForCurrentUser, temporary: files.temporaryDirectory)
    try require(try bundleBuild(destination) == oldBuild, "The installed app changed during the update. Please retry.")
    let applications = destination.deletingLastPathComponent()
    try require(files.isWritableFile(atPath: applications.path) && files.isWritableFile(atPath: destination.path),
                "The Applications folder is not writable. The installed app was retained.")
    let incoming = applications.appendingPathComponent(".StanMicBridge-incoming-\(UUID().uuidString).app")
    let backup = applications.appendingPathComponent("Stan Mic Bridge-backup-\(Int(Date().timeIntervalSince1970))-\(UUID().uuidString).app")
    try files.copyItem(at: resolvedStage, to: incoming)
    try LocalSigning.prepareDownloadedApp(at: incoming, installedApp: destination)
    try verify(incoming)
    try require(try bundleBuild(incoming) == newBuild, "The staged build changed during installation.")
    var launchTime: Date?
    try replace(destination: destination, incoming: incoming, backup: backup,
                move: { try files.moveItem(at: $0, to: $1) },
                launch: { app in
                    let started = Date()
                    launchTime = started
                    var launchArguments = ["-n", app.path, "--args", "--update-ready", receipt.path]
                    if resumeRequested {
                        launchArguments += ["--resume-update", try createResumeGrant(root: stagingRoot, build: String(newBuild))]
                    }
                    try run("/usr/bin/open", launchArguments)
                    try waitForReadiness(receipt: receipt, build: String(newBuild), alive: { pid in
                        guard kill(pid, 0) == 0, let running = NSRunningApplication(processIdentifier: pid) else { return false }
                        return matchingLaunch(running, destination: app, since: started)
                    })
                },
                beforeRollback: {
                    if let started = launchTime { try stopFailedLaunch(destination: destination, since: started) }
                },
                exists: { files.fileExists(atPath: $0.path) })
    // Only remove our specifically named staging root, after successful launch.
    if expanded.lastPathComponent == "expanded",
       stagingRoot.deletingLastPathComponent().path == temporary.path,
       stagingRoot.lastPathComponent.hasPrefix(prefix),
       UUID(uuidString: String(stagingRoot.lastPathComponent.dropFirst(prefix.count))) != nil {
        try? files.removeItem(at: stagingRoot)
    }
}
private func selfTest() throws {
    let root = files.temporaryDirectory.appendingPathComponent("StanMicUpdater-test-\(UUID().uuidString)")
    try files.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? files.removeItem(at: root) }
    let intentPath = root.appendingPathComponent("resume-intent.json")
    for sample in [ResumeIntent(parentPID: 123, build: "6", createdAt: 1000),
                   ResumeIntent(parentPID: 124, build: "6", createdAt: 1000),
                   ResumeIntent(parentPID: 123, build: "5", createdAt: 1000),
                   ResumeIntent(parentPID: 123, build: "6", createdAt: 399)] {
        try JSONEncoder().encode(sample).write(to: intentPath)
        try files.setAttributes([.posixPermissions: 0o600], ofItemAtPath: intentPath.path)
        let accepted = consumeResumeIntent(root: root, parent: 123, build: "6", now: 1000)
        try require(accepted == (sample.parentPID == 123 && sample.build == "6" && sample.createdAt == 1000), "Resume intent boundary check failed.")
        try require(!consumeResumeIntent(root: root, parent: 123, build: "6", now: 1000), "A resume intent could be replayed.")
    }
    for failure in [0, 2, 3, 4, 5] {
        let caseRoot = root.appendingPathComponent("case-\(failure)")
        try files.createDirectory(at: caseRoot, withIntermediateDirectories: true)
        let dest = caseRoot.appendingPathComponent("old.app")
        let incoming = caseRoot.appendingPathComponent("new.app")
        let backup = caseRoot.appendingPathComponent("backup.app")
        let receipt = caseRoot.appendingPathComponent("update-ready.json")
        try Data("old".utf8).write(to: dest)
        try Data("new".utf8).write(to: incoming)
        var moves = 0
        var failed = false
        do {
            try replace(destination: dest, incoming: incoming, backup: backup, move: { a, b in
                moves += 1
                if failure == 2 && moves == 2 { throw UpdateError.message("injected move failure") }
                try files.moveItem(at: a, to: b)
            }, launch: { _ in
                if failure == 3 { throw UpdateError.message("injected launch failure") }
                if failure != 4 && failure != 5 {
                    try Data("{\"pid\":123,\"build\":\"5\"}".utf8).write(to: receipt)
                }
                try waitForReadiness(receipt: receipt, build: "5", timeout: 0, alive: { $0 == 123 })
            }, beforeRollback: {
                if failure == 5 { throw UpdateError.message("injected inability to stop launched app") }
            }, exists: { files.fileExists(atPath: $0.path) })
        } catch { failed = true }
        try require(failed == (failure != 0), "Failure injection did not produce the expected result.")
        let actual = try String(contentsOf: dest, encoding: .utf8)
        try require(actual == (failure == 0 || failure == 5 ? "new" : "old"), "Replacement or rollback failed.")
        if failure == 0 || failure == 5 {
            try require(try String(contentsOf: backup, encoding: .utf8) == "old", "Original backup was lost.")
        }
    }
    let badReceipt = root.appendingPathComponent("wrong-build.json")
    try Data("{\"pid\":123,\"build\":\"4\"}".utf8).write(to: badReceipt)
    do {
        try waitForReadiness(receipt: badReceipt, build: "5", timeout: 0, alive: { _ in true })
        throw UpdateError.message("Wrong build was accepted.")
    } catch {
        try require(String(describing: error).contains("did not confirm"), "Wrong-build receipt was not rejected.")
    }
    do {
        try waitForParent(getpid(), timeout: 0)
        throw UpdateError.message("Parent timeout test unexpectedly passed.")
    } catch {
        try require(String(describing: error).contains("did not exit"), "Parent timeout was not enforced.")
    }
    print("Updater transaction, startup-readiness, safe-rollback and parent-timeout tests passed.")
}
// CI exercises the actual LaunchServices/receipt path with an app that starts
// stopped. This mode never replaces an installation or starts microphone input.
private func testStartup(_ path: String, resume: Bool = false) throws {
    try require(path.hasPrefix("/"), "The startup test requires an absolute app path.")
    let app = try canonicalAnchor(URL(fileURLWithPath: path))
    try verify(app)
    let build = try bundleBuild(app)
    let root = try canonicalAnchor(files.temporaryDirectory)
        .appendingPathComponent("StanMicBridge-update-\(UUID().uuidString)")
    try files.createDirectory(at: root, withIntermediateDirectories: false,
                              attributes: [.posixPermissions: 0o700])
    defer { try? files.removeItem(at: root) }
    let receipt = root.appendingPathComponent("update-ready.json")
    let started = Date()
    do {
        var launchArguments = ["-n", app.path, "--args", "--test-update-startup", receipt.path]
        if resume {
            let intentFile = root.appendingPathComponent("resume-intent.json")
            let intent = ResumeIntent(parentPID: getpid(), build: String(build), createdAt: Date().timeIntervalSince1970)
            try JSONEncoder().encode(intent).write(to: intentFile, options: .atomic)
            try files.setAttributes([.posixPermissions: 0o600], ofItemAtPath: intentFile.path)
            try require(consumeResumeIntent(root: root, parent: getpid(), build: String(build)), "The helper rejected the valid resume intent.")
            try require(!consumeResumeIntent(root: root, parent: getpid(), build: String(build)), "A consumed resume intent was reused.")
            launchArguments = ["-n", app.path, "--args", "--test-update-resume", receipt.path,
                               "--resume-update", try createResumeGrant(root: root, build: String(build))]
        }
        try run("/usr/bin/open", launchArguments)
        try waitForReadiness(receipt: receipt, build: String(build), alive: { pid in
            guard kill(pid, 0) == 0, let running = NSRunningApplication(processIdentifier: pid) else { return false }
            return matchingLaunch(running, destination: app, since: started)
        })
        let result = try JSONDecoder().decode(ReadyReceipt.self, from: Data(contentsOf: receipt))
        try require(result.resumeGrantConsumed == resume, "The app did not report the expected one-shot resume consumption.")
        try require(!files.fileExists(atPath: root.appendingPathComponent("resume-once.json").path), "The one-shot resume grant was not consumed.")
    } catch {
        let startupError = error
        try stopFailedLaunch(destination: app, since: started)
        throw startupError
    }
    try stopFailedLaunch(destination: app, since: started)
    print("Real LaunchServices startup receipt and safe termination passed; microphone remained stopped.")
}
private func signingSetupStage(_ path: String) throws -> URL {
    try require(path.hasPrefix("/"), "The installer staging app must use an absolute path.")
    let stage = try noSymlinksUnderAnchor(URL(fileURLWithPath: normalizedSeparators(path)), anchor: files.temporaryDirectory)
    try require(stage.lastPathComponent == "Stan Mic Bridge.app", "Unexpected installer staging app name.")
    let executable = try canonicalAnchor(URL(fileURLWithPath: CommandLine.arguments[0]))
    try require(!executable.path.hasPrefix(stage.path + "/"),
                "Run a verified copy of the signing helper outside the staging app so it does not re-sign its own running executable.")
    try verify(stage)
    return stage
}
private func testBootstrapPaths(_ source: URL) throws {
    let temporary = files.temporaryDirectory
    let name = "stan-mic-bootstrap-test-\(UUID().uuidString)"
    let root = temporary.appendingPathComponent(name)
    try files.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? files.removeItem(at: root) }
    let staged = root.appendingPathComponent("Stan Mic Bridge.app")
    try verify(source)
    try files.copyItem(at: source, to: staged)
    let raw = temporary.path + "/" + name + "/Stan Mic Bridge.app"
    let canonical = try canonicalAnchor(temporary).path + "/" + name + "/Stan Mic Bridge.app"
    let repeated = temporary.path + "///" + name + "//Stan Mic Bridge.app"
    let repeatedCanonical = try canonicalAnchor(temporary).path + "//" + name + "///Stan Mic Bridge.app"
    let oldCandidate = URL(fileURLWithPath: repeated).path
    print("Bootstrap path diagnostic: Foundation retains repeated separators = \(oldCandidate.contains("//"))")
    let expected = try canonicalAnchor(staged).path
    for spelling in [raw, canonical, repeated, repeatedCanonical] {
        try require(try signingSetupStage(spelling).path == expected,
                    "The bootstrap signing preflight rejected an equivalent separator/anchor spelling.")
    }
    print("Bootstrap signing preflight accepted raw/canonical temp anchors and repeated separators.")
    for traversal in [temporary.path + "/./" + name + "/Stan Mic Bridge.app",
                      temporary.path + "/" + name + "/../" + name + "/Stan Mic Bridge.app"] {
        var rejected = false
        do { _ = try signingSetupStage(traversal) }
        catch { rejected = String(describing: error).contains("invalid path component") }
        try require(rejected, "The bootstrap signing preflight accepted a traversal token.")
    }
    let saved = root.appendingPathComponent("saved.app")
    try files.moveItem(at: staged, to: saved)
    try files.createSymbolicLink(at: staged, withDestinationURL: saved)
    var rejectedLink = false
    do { _ = try signingSetupStage(repeated) }
    catch { rejectedLink = String(describing: error).contains("symbolic link") }
    try files.removeItem(at: staged)
    try files.moveItem(at: saved, to: staged)
    try require(rejectedLink, "The bootstrap signing preflight accepted a staged app symlink.")
    print("Bootstrap signing preflight rejected traversal and descendant symlinks; no signing identity was accessed.")
}
@main
struct UpdaterMain {
static func main() {
do {
    let arguments = Array(CommandLine.arguments.dropFirst())
    if arguments == ["--self-test"] { try selfTest() }
    else if arguments.count == 2 && arguments[0] == "--test-bootstrap-paths" {
        try testBootstrapPaths(URL(fileURLWithPath: arguments[1]))
    }
    else if arguments.count == 2 && arguments[0] == "--test-local-signing" {
        try LocalSigningTests.run(app: URL(fileURLWithPath: arguments[1]))
    }
    else if arguments.count == 2 && arguments[0] == "--setup-local-signing" {
        try LocalSigning.setup(app: signingSetupStage(arguments[1]))
        print("The staging app now uses the pinned local signing identity.")
    }
    else if arguments.count == 3 && arguments[0] == "--prepare-local-signing" {
        let stage = try signingSetupStage(arguments[1])
        let home = files.homeDirectoryForCurrentUser
        let supplied = URL(fileURLWithPath: try normalizedSeparators(arguments[2]))
        let expected = home.appendingPathComponent("Applications/Stan Mic Bridge.app")
        let canonicalExpected = try canonicalAnchor(home).appendingPathComponent("Applications/Stan Mic Bridge.app")
        try require(supplied.path == expected.path || supplied.path == canonicalExpected.path,
                    "The installer destination must be ~/Applications/Stan Mic Bridge.app.")
        let installed = files.fileExists(atPath: supplied.path)
            ? try noSymlinksUnderAnchor(supplied, anchor: home) : nil
        try LocalSigning.prepareInstallerApp(at: stage, installedApp: installed)
        print("Installer signing policy verified.")
    }
    else if arguments == ["--test-paths"] { try testPaths() }
    else if arguments.count == 2 && arguments[0] == "--test-install-paths" {
        try testPaths(builtApp: URL(fileURLWithPath: arguments[1]))
    }
    else if arguments.count == 2 && arguments[0] == "--test-startup" { try testStartup(arguments[1]) }
    else if arguments.count == 2 && arguments[0] == "--test-startup-resume" { try testStartup(arguments[1], resume: true) }
    else { try install(arguments) }
} catch {
    if CommandLine.arguments.dropFirst().first?.hasPrefix("--") == true {
        let operation = CommandLine.arguments.dropFirst().first ?? ""
        let prefix = operation == "--setup-local-signing" || operation == "--prepare-local-signing"
            ? "Local signing setup failed" : "Updater test failed"
        fputs("\(prefix): \(error)\n", stderr)
    } else {
        NSApplication.shared.setActivationPolicy(.accessory)
        let alert = NSAlert()
        alert.messageText = "Stan Mic Bridge 更新未完成"
        alert.informativeText = String(describing: error)
        alert.addButton(withTitle: "好")
        NSApplication.shared.activate(ignoringOtherApps: true)
        alert.runModal()
    }
    exit(1)
}
}
}
