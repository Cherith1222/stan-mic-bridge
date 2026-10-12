import AppKit
import AVFoundation
import Security

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
    // Native login Keychain: suitable for a locally built, ad-hoc signed app.
    // The secret is never stored in UserDefaults or a launch command.
    static var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: "com.stan.micbridge",
         kSecAttrAccount as String: "receiver"]
    }

    static func load() -> Connection? {
        var search = query
        search[kSecReturnData as String] = true
        search[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(search as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return try? JSONDecoder().decode(Connection.self, from: data)
    }

    static func save(_ connection: Connection) -> Bool {
        guard let data = try? JSONEncoder().encode(connection) else { return false }
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
    let tag_name: String
    let html_url: String
    let body: String?
    let draft: Bool
    let prerelease: Bool

    var stableVersion: StableVersion? {
        guard !draft, !prerelease else { return nil }
        return StableVersion(tag_name)
    }
    var trustedURL: URL? {
        guard stableVersion != nil, let parts = URLComponents(string: html_url),
              parts.scheme == "https", parts.host == "github.com", parts.port == nil,
              parts.user == nil, parts.password == nil, parts.query == nil, parts.fragment == nil,
              parts.percentEncodedPath == "/Cherith1222/stan-mic-bridge/releases/tag/" + tag_name else { return nil }
        return parts.url
    }
}

private func testUpdatePolicy() {
    precondition(StableVersion("1.9.0")! < StableVersion("1.10.0")!)
    precondition(StableVersion("v1.1.0")! == StableVersion("1.1.0")!)
    precondition(StableVersion("2.0.0")! > StableVersion("1.99.99")!)
    for bad in ["1.0", "01.0.0", "1.0.0-beta", "1.0.0+dev", "1.-1.0", "1.0.0/"] {
        precondition(StableVersion(bad) == nil)
    }
    let canonical = "https://github.com/Cherith1222/stan-mic-bridge/releases/tag/v1.1.0"
    func release(_ url: String, draft: Bool = false, prerelease: Bool = false) -> PublicRelease {
        PublicRelease(tag_name: "v1.1.0", html_url: url, body: nil, draft: draft, prerelease: prerelease)
    }
    precondition(release(canonical).trustedURL != nil)
    precondition(release(canonical, draft: true).trustedURL == nil)
    precondition(release(canonical, prerelease: true).trustedURL == nil)
    for bad in [canonical + "?x=1", canonical + "#x", canonical + "/extra",
                canonical.replacingOccurrences(of: "https:", with: "http:"),
                canonical.replacingOccurrences(of: "github.com", with: "github.com.evil.test"),
                canonical.replacingOccurrences(of: "Cherith1222", with: "someone"),
                canonical.replacingOccurrences(of: "v1.1.0", with: "v2.0.0")] {
        precondition(release(bad).trustedURL == nil)
    }
    print("Update policy checks passed")
}

private final class AudioMailbox {
    struct Packet {
        let bytes: Data
        let captured: TimeInterval
    }
    private let lock = NSLock()
    private var packets: [Packet] = []
    private var byteCount = 0
    private var fault = false

    func put(_ data: Data) {
        lock.lock()
        defer { lock.unlock() }
        // 100 ms of 48 kHz float32 audio. Drop oldest audio on congestion.
        guard !data.isEmpty, data.count <= 19200 else { fault = true; return }
        while !packets.isEmpty && (byteCount + data.count > 19200 || packets.count >= 8) {
            byteCount -= packets.removeFirst().bytes.count
        }
        packets.append(Packet(bytes: data, captured: ProcessInfo.processInfo.systemUptime))
        byteCount += data.count
    }

    func take() -> Packet? {
        lock.lock()
        defer { lock.unlock() }
        let now = ProcessInfo.processInfo.systemUptime
        while !packets.isEmpty {
            let packet = packets.removeFirst()
            byteCount -= packet.bytes.count
            if now - packet.captured < 0.15 { return packet }
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

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem!
    private let stateItem = NSMenuItem(title: "已停止", action: nil, keyEquivalent: "")
    private let startItem = NSMenuItem(title: "開始傳送", action: #selector(start), keyEquivalent: "")
    private let stopItem = NSMenuItem(title: "停止傳送", action: #selector(stop), keyEquivalent: "")
    private let configureItem = NSMenuItem(title: "設定連線…", action: #selector(configure), keyEquivalent: "")
    private let forgetItem = NSMenuItem(title: "清除已儲存的連線…", action: #selector(forget), keyEquivalent: "")
    private let updateItem = NSMenuItem(title: "檢查更新…", action: #selector(checkUpdates), keyEquivalent: "")
    private var updateSession: URLSession?
    private var updatePanel: NSPanel?
    private var releaseURL: URL?
    private var connection: Connection?
    private var enabled = false
    private var sleeping = false
    private var generation = 0
    private var failures = 0
    private var socket: URLSessionWebSocketTask?
    private var session: URLSession?
    private var engine: AVAudioEngine?
    private var mailbox: AudioMailbox?
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
        menu.autoenablesItems = false
        menu.addItem(stateItem)
        menu.addItem(.separator())
        for item in [startItem, stopItem, configureItem, forgetItem] {
            item.target = self
            menu.addItem(item)
        }
        menu.addItem(.separator())
        updateItem.target = self
        menu.addItem(updateItem)
        menu.addItem(.separator())
        let quit = NSMenuItem(title: "結束 Stan Mic Bridge", action: #selector(quitApp), keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)
        statusItem.menu = menu
        connection = Credentials.load()
        show(connection == nil ? "請先設定連線" : "已停止")
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
        if connection == nil { DispatchQueue.main.async { self.configure() } }
    }

    private func show(_ text: String) {
        stateItem.title = text
        stateItem.isEnabled = false
        statusItem.button?.title = ready ? "Mic ●" : (enabled ? "Mic …" : "Mic ○")
        statusItem.button?.toolTip = "Stan Mic Bridge — " + text
        startItem.isEnabled = !enabled && connection != nil
        stopItem.isEnabled = enabled
        configureItem.isEnabled = !enabled
        forgetItem.isEnabled = !enabled && connection != nil
    }

    @objc private func checkUpdates() {
        guard updateSession == nil else { return }
        updateItem.isEnabled = false
        updateItem.title = "正在檢查更新…"
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 15
        configuration.timeoutIntervalForResource = 20
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCredentialStorage = nil
        configuration.urlCache = nil
        let client = URLSession(configuration: configuration, delegate: NoRedirectDelegate(), delegateQueue: nil)
        updateSession = client
        var request = URLRequest(url: URL(string: "https://api.github.com/repos/Cherith1222/stan-mic-bridge/releases/latest")!)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")
        request.setValue("Stan-Mic-Bridge-Update-Check", forHTTPHeaderField: "User-Agent")
        client.dataTask(with: request) { [weak self] data, response, error in
            DispatchQueue.main.async {
                guard let self = self else { client.finishTasksAndInvalidate(); return }
                self.updateSession = nil
                client.finishTasksAndInvalidate()
                self.updateItem.isEnabled = true
                self.updateItem.title = "檢查更新…"
                if error != nil {
                    self.showUpdate("無法檢查更新", "連線逾時或網路暫時無法使用，請稍後再試。麥克風傳送不受影響。")
                    return
                }
                guard let response = response as? HTTPURLResponse else {
                    self.showUpdate("無法檢查更新", "GitHub 回應無法辨識，請稍後再試。")
                    return
                }
                if response.statusCode == 404 {
                    self.showUpdate("尚無可用版本", "GitHub 目前沒有可取得的正式發布版本。你可以繼續使用目前版本。")
                    return
                }
                if response.statusCode == 403 || response.statusCode == 429 {
                    self.showUpdate("GitHub 暫時限制請求", "可能已達公開 API 的請求限制，或 GitHub 拒絕此請求。請稍後再手動檢查。")
                    return
                }
                guard response.statusCode == 200, let data = data, data.count <= 1048576,
                      let release = try? JSONDecoder().decode(PublicRelease.self, from: data) else {
                    self.showUpdate("無法檢查更新", "GitHub 回應不完整或服務暫時無法使用，請稍後再試。")
                    return
                }
                guard let latest = release.stableVersion, let url = release.trustedURL else {
                    self.showUpdate("沒有可用的正式更新", "收到的版本或發布網址無法確認；不會開啟或安裝此更新。")
                    return
                }
                let currentText = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "未知"
                guard let current = StableVersion(currentText) else {
                    self.showUpdate("無法判斷目前版本", "請到 GitHub 的正式發布頁面確認目前的安裝版本。")
                    return
                }
                guard latest > current else {
                    self.showUpdate("已是最新版本", "目前版本：\(currentText)\n最新正式版本：\(release.tag_name)")
                    return
                }
                let rawNotes = release.body ?? "此版本未提供更新說明。"
                let notes = String(rawNotes.prefix(6000)) + (rawNotes.count > 6000 ? "\n…完整說明請查看發布頁面。" : "")
                self.showUpdate("有新版本可用", "目前版本：\(currentText)\n最新版本：\(release.tag_name)\n\n\(notes)\n\n按下方按鈕只會開啟 GitHub 發布頁面。請自行下載及執行安裝；安裝前先停止傳送並結束程式。", url: url)
            }
        }.resume()
    }

    // A modeless panel leaves the audio run loop running while release notes are read.
    private func showUpdate(_ title: String, _ detail: String, url: URL? = nil) {
        updatePanel?.close()
        releaseURL = url
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
        if url != nil {
            let open = NSButton(title: "查看更新與安裝", target: self, action: #selector(openRelease))
            open.frame = NSRect(x: 20, y: 20, width: 180, height: 30)
            open.bezelStyle = .rounded
            panel.contentView?.addSubview(open)
        }
        updatePanel = panel
        panel.center()
        NSApp.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
    }

    @objc private func closeUpdatePanel() { updatePanel?.close() }
    @objc private func openRelease() {
        guard let url = releaseURL else { return }
        if !NSWorkspace.shared.open(url) {
            showUpdate("無法開啟瀏覽器", "請稍後再試，或手動前往 github.com/Cherith1222/stan-mic-bridge/releases。")
        }
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
            message("無法儲存鑰匙圈", "請確認登入鑰匙圈已解鎖，再重新設定。")
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
        alert.informativeText = "只會刪除此程式的鑰匙圈項目，Windows 接收端不會改變。"
        alert.addButton(withTitle: "清除")
        alert.addButton(withTitle: "取消")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        guard Credentials.remove() else {
            message("無法清除鑰匙圈", "請確認登入鑰匙圈已解鎖後重試。")
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
        show("等待麥克風權限")
        let epoch = generation
        AVCaptureDevice.requestAccess(for: .audio) { [weak self] granted in
            DispatchQueue.main.async {
                guard let self = self, self.enabled, self.generation == epoch else { return }
                guard granted else {
                    self.stop()
                    self.show("麥克風權限未開啟")
                    self.message("需要麥克風權限", "請在系統設定的「隱私權與安全性 → 麥克風」允許 Stan Mic Bridge，再按開始。")
                    return
                }
                // Prevent App Nap while explicitly enabled, without preventing sleep.
                self.activity = ProcessInfo.processInfo.beginActivity(options: [.userInitiatedAllowingIdleSystemSleep],
                                                                       reason: "Live microphone transmission")
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
        let box = AudioMailbox()
        self.engine = engine
        mailbox = box
        input.installTap(onBus: 0, bufferSize: 1024, format: source) { buffer, _ in
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
        for observer in workspaceObservers { NSWorkspace.shared.notificationCenter.removeObserver(observer) }
    }
}

if CommandLine.arguments.contains("--test-updates") {
    testUpdatePolicy()
    exit(0)
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
