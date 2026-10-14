// SentinelCore для macOS: значок в строке меню, который запускает сервер и открывает панель.
//
// Данные:     ~/Library/Application Support/SentinelCore (настройки, правила, события, ключ администратора)
// Журнал:     ~/Library/Logs/SentinelCore/server.log
// Сервер — sentinel-server из пакета приложения; работает, пока открыто приложение.

import AppKit
import Darwin
import Security
#if canImport(ServiceManagement)
import ServiceManagement
#endif

private let appVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem!
    private let menu = NSMenu()
    private let stateItem = NSMenuItem(title: "Запускается…", action: nil, keyEquivalent: "")
    private var loginItem: NSMenuItem?

    private var server: Process?
    private var logHandle: FileHandle?
    private var port = 8080
    private var stopping = false
    private var crashes: [Date] = []
    private var healthTimer: Timer?
    private var openPanelWhenReady = false
    private var signalSources: [DispatchSourceSignal] = []

    private let fm = FileManager.default
    private lazy var supportDir: URL = {
        let base = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("SentinelCore", isDirectory: true)
    }()
    private lazy var logDir: URL = {
        let base = fm.urls(for: .libraryDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("Logs/SentinelCore", isDirectory: true)
    }()
    private var configURL: URL { supportDir.appendingPathComponent("sentinel.yaml") }
    private var keyURL: URL { supportDir.appendingPathComponent("admin-key.txt") }
    private var pidURL: URL { supportDir.appendingPathComponent("server.pid") }
    private var logURL: URL { logDir.appendingPathComponent("server.log") }
    private var resources: URL { Bundle.main.resourceURL! }
    private var serverBinary: URL { resources.appendingPathComponent("bin/sentinel-server") }

    // MARK: - запуск приложения

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildMenu()
        catchSignals()
        do {
            try prepare()
            // при каждом запуске приложения панель открывается сама (кроме автоматической проверки)
            openPanelWhenReady = ProcessInfo.processInfo.environment["SENTINEL_APP_NO_BROWSER"] == nil
            startServer()
        } catch {
            setState("Ошибка: \(error.localizedDescription)", ok: false)
            alert("Не удалось подготовить SentinelCore", error.localizedDescription)
        }
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        stopServer()
        return .terminateNow
    }

    // Выход по сигналу (например, при выключении компьютера или kill) тоже останавливает сервер.
    private func catchSignals() {
        for sig in [SIGTERM, SIGINT, SIGHUP] {
            signal(sig, SIG_IGN)
            let src = DispatchSource.makeSignalSource(signal: sig, queue: .main)
            src.setEventHandler { [weak self] in
                self?.stopServer()
                exit(0)
            }
            src.resume()
            signalSources.append(src)
        }
    }

    // MARK: - меню

    private func buildMenu() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button {
            if let img = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: "SentinelCore") {
                img.isTemplate = true
                button.image = img
            } else {
                button.title = "SC"
            }
            button.toolTip = "SentinelCore SIEM"
        }
        let title = NSMenuItem(title: "SentinelCore \(appVersion)", action: nil, keyEquivalent: "")
        title.isEnabled = false
        menu.addItem(title)
        stateItem.isEnabled = false
        menu.addItem(stateItem)
        menu.addItem(.separator())
        menu.addItem(item("Открыть панель", #selector(openPanel), "o"))
        menu.addItem(item("Скопировать ключ администратора", #selector(copyKey), "k"))
        menu.addItem(.separator())
        menu.addItem(item("Перезапустить сервер", #selector(restartServer), "r"))
        menu.addItem(item("Настройки (sentinel.yaml)…", #selector(openConfig), ","))
        menu.addItem(item("Показать папку с данными", #selector(showData), ""))
        menu.addItem(item("Журнал сервера", #selector(showLog), "l"))
        if #available(macOS 13.0, *) {
            let li = item("Открывать при входе в систему", #selector(toggleLogin), "")
            li.state = SMAppService.mainApp.status == .enabled ? .on : .off
            menu.addItem(li)
            loginItem = li
        }
        menu.addItem(.separator())
        menu.addItem(item("Выход", #selector(quit), "q"))
        statusItem.menu = menu
    }

    private func item(_ title: String, _ action: Selector, _ key: String) -> NSMenuItem {
        let it = NSMenuItem(title: title, action: action, keyEquivalent: key)
        it.target = self
        return it
    }

    private func setState(_ text: String, ok: Bool) {
        stateItem.title = (ok ? "● " : "○ ") + text
    }

    // MARK: - подготовка папок, настроек и ключа

    private func prepare() throws {
        try fm.createDirectory(at: supportDir, withIntermediateDirectories: true)
        try fm.createDirectory(at: logDir, withIntermediateDirectories: true)
        try fm.createDirectory(at: supportDir.appendingPathComponent("data"), withIntermediateDirectories: true)
        let rules = supportDir.appendingPathComponent("rules")
        if !fm.fileExists(atPath: rules.path) {
            try fm.copyItem(at: resources.appendingPathComponent("rules"), to: rules)
        }
        if !fm.fileExists(atPath: keyURL.path) {
            try (newKey() + "\n").write(to: keyURL, atomically: true, encoding: .utf8)
            try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyURL.path)
        }
        if !fm.fileExists(atPath: configURL.path) {
            port = freePort(from: 8080) ?? 8080
            let cfg = """
            # Настройки SentinelCore (приложение для Mac).
            # После правки: меню SentinelCore в строке меню → «Перезапустить сервер».
            # Все возможности (уведомления, автоблокировка, чёрные списки, отчёты на почту) —
            # в sentinel.example.yaml: https://github.com/KishoHiga/SIEM/blob/main/sentinel.example.yaml

            # 127.0.0.1 — только этот Mac. Чтобы принимать логи от агентов с других серверов,
            # поставьте 0.0.0.0:\(port) и включите HTTPS (sentinel-server gen-cert, раздел tls:).
            listen: 127.0.0.1:\(port)

            data_dir: \(supportDir.appendingPathComponent("data").path)
            rules_dir: \(rules.path)
            retention_days: 90

            """
            try cfg.write(to: configURL, atomically: true, encoding: .utf8)
        }
        port = readPort() ?? port
    }

    private func newKey() -> String {
        var bytes = [UInt8](repeating: 0, count: 24)
        if SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) != errSecSuccess {
            for i in bytes.indices { bytes[i] = UInt8.random(in: 0...255) }
        }
        return "snt_" + bytes.map { String(format: "%02x", $0) }.joined()
    }

    private var adminKey: String {
        (try? String(contentsOf: keyURL, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    }

    private func readPort() -> Int? {
        guard let text = try? String(contentsOf: configURL, encoding: .utf8) else { return nil }
        for raw in text.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard line.hasPrefix("listen:") else { continue }
            var value = line.dropFirst("listen:".count).trimmingCharacters(in: .whitespaces)
            if let hash = value.firstIndex(of: "#") { value = String(value[..<hash]).trimmingCharacters(in: .whitespaces) }
            value = value.trimmingCharacters(in: CharacterSet(charactersIn: "'\""))
            if let colon = value.lastIndex(of: ":"), let p = Int(value[value.index(after: colon)...]) { return p }
        }
        return nil
    }

    private func freePort(from start: Int) -> Int? {
        for p in start..<(start + 20) where portIsFree(p) { return p }
        return nil
    }

    private func portIsFree(_ p: Int) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        if fd < 0 { return false }
        defer { close(fd) }
        var yes: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(UInt16(p).bigEndian)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        return rc == 0
    }

    // MARK: - сервер

    private func startServer() {
        killLeftover()
        guard fm.isExecutableFile(atPath: serverBinary.path) else {
            setState("Нет программы сервера в приложении", ok: false)
            return
        }
        if !fm.fileExists(atPath: logURL.path) { fm.createFile(atPath: logURL.path, contents: nil) }
        logHandle = try? FileHandle(forWritingTo: logURL)
        logHandle?.seekToEndOfFile()

        let p = Process()
        p.executableURL = serverBinary
        p.arguments = ["run", "-c", configURL.path]
        p.currentDirectoryURL = supportDir
        var env = ProcessInfo.processInfo.environment
        env["SENTINEL_WEB_DIR"] = resources.appendingPathComponent("web").path
        env["SENTINEL_ADMIN_KEY"] = adminKey  // используется только при самом первом запуске
        p.environment = env
        if let h = logHandle {
            p.standardOutput = h
            p.standardError = h
        }
        p.terminationHandler = { [weak self] proc in
            DispatchQueue.main.async { self?.serverExited(proc.terminationStatus) }
        }
        do {
            try p.run()
        } catch {
            setState("Не запустился: \(error.localizedDescription)", ok: false)
            return
        }
        server = p
        try? "\(p.processIdentifier)\n".write(to: pidURL, atomically: true, encoding: .utf8)
        setState("Запускается… (порт \(port))", ok: false)
        waitForHealth()
    }

    // Сервер, оставшийся от прошлого запуска (если приложение было закрыто аварийно), держит порт.
    private func killLeftover() {
        guard let text = try? String(contentsOf: pidURL, encoding: .utf8),
              let pid = pid_t(text.trimmingCharacters(in: .whitespacesAndNewlines)), pid > 1 else { return }
        if processName(pid).hasSuffix("sentinel-server") {
            kill(pid, SIGTERM)
            for _ in 0..<50 {
                if kill(pid, 0) != 0 { break }
                usleep(100_000)
            }
        }
        try? fm.removeItem(at: pidURL)
    }

    private func processName(_ pid: pid_t) -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/ps")
        p.arguments = ["-p", "\(pid)", "-o", "comm="]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return "" }
        p.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return (String(data: data, encoding: .utf8) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func waitForHealth() {
        healthTimer?.invalidate()
        let started = Date()
        healthTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] t in
            guard let self = self else { return t.invalidate() }
            guard self.server?.isRunning == true else { return t.invalidate() }
            self.checkHealth { ok in
                guard ok else {
                    if Date().timeIntervalSince(started) > 30 {
                        t.invalidate()
                        self.setState("Сервер не отвечает — см. «Журнал сервера»", ok: false)
                    }
                    return
                }
                t.invalidate()
                self.setState("Работает — http://127.0.0.1:\(self.port)", ok: true)
                if self.openPanelWhenReady {
                    self.openPanelWhenReady = false
                    self.openPanel()
                }
            }
        }
    }

    private func checkHealth(_ done: @escaping (Bool) -> Void) {
        guard let url = URL(string: "http://127.0.0.1:\(port)/health") else { return done(false) }
        var req = URLRequest(url: url)
        req.timeoutInterval = 2
        URLSession.shared.dataTask(with: req) { _, resp, _ in
            let ok = (resp as? HTTPURLResponse)?.statusCode == 200
            DispatchQueue.main.async { done(ok) }
        }.resume()
    }

    private func serverExited(_ status: Int32) {
        server = nil
        try? fm.removeItem(at: pidURL)
        if stopping { return }
        // упал — перезапуск, но не чаще 5 раз за 2 минуты
        let now = Date()
        crashes = crashes.filter { now.timeIntervalSince($0) < 120 } + [now]
        if crashes.count > 5 {
            setState("Сервер остановился (код \(status)) — см. «Журнал сервера»", ok: false)
            return
        }
        setState("Перезапуск после ошибки (код \(status))…", ok: false)
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in self?.startServer() }
    }

    private func stopServer() {
        stopping = true
        healthTimer?.invalidate()
        guard let p = server, p.isRunning else { return }
        p.terminate()  // SIGTERM: сервер дописывает данные на диск и выходит
        let deadline = Date().addingTimeInterval(15)
        while p.isRunning && Date() < deadline { usleep(100_000) }
        if p.isRunning { kill(p.processIdentifier, SIGKILL) }
        try? fm.removeItem(at: pidURL)
        server = nil
    }

    // MARK: - действия меню

    @objc private func openPanel() {
        let key = adminKey
        let suffix = key.isEmpty ? "" : "#key=\(key)"  // панель сама войдёт и уберёт ключ из адреса
        if let url = URL(string: "http://127.0.0.1:\(port)/\(suffix)") { NSWorkspace.shared.open(url) }
    }

    @objc private func copyKey() {
        let key = adminKey
        guard !key.isEmpty else { return alert("Ключ не найден", keyURL.path) }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(key, forType: .string)
        setStateFlash("Ключ скопирован")
    }

    private func setStateFlash(_ text: String) {
        let old = stateItem.title
        stateItem.title = "✓ " + text
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self] in
            if self?.stateItem.title == "✓ " + text { self?.stateItem.title = old }
        }
    }

    @objc private func restartServer() {
        stopServer()
        stopping = false
        crashes = []
        port = readPort() ?? port
        startServer()
    }

    @objc private func openConfig() {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        p.arguments = ["-e", configURL.path]  // TextEdit
        try? p.run()
    }

    @objc private func showData() {
        NSWorkspace.shared.activateFileViewerSelecting([supportDir])
    }

    @objc private func showLog() {
        NSWorkspace.shared.open(logURL)
    }

    @objc private func toggleLogin() {
        guard #available(macOS 13.0, *) else { return }
        do {
            if SMAppService.mainApp.status == .enabled {
                try SMAppService.mainApp.unregister()
            } else {
                try SMAppService.mainApp.register()
            }
        } catch {
            alert("Не получилось изменить автозапуск",
                  "Добавьте SentinelCore вручную: Системные настройки → Основные → Объекты входа.\n\n\(error.localizedDescription)")
        }
        loginItem?.state = SMAppService.mainApp.status == .enabled ? .on : .off
    }

    @objc private func quit() {
        NSApp.terminate(nil)
    }

    private func alert(_ title: String, _ text: String) {
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.messageText = title
        a.informativeText = text
        a.runModal()
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)  // только значок в строке меню, без значка в Dock
app.run()
