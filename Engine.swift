import Foundation
import SwiftUI
import AppKit
import Combine

// MARK: - Modelle

struct Port: Identifiable, Hashable {
    var id: String { service }
    let service: String   // Name in den Systemeinstellungen, z. B. "USB 10/100/1000 LAN"
    let device: String    // BSD-Name, z. B. "en5"
}

struct StaticProfile: Identifiable, Codable, Hashable {
    var id = UUID()
    var name = "Profil"
    var ip = "192.168.1.50"
    var mask = "255.255.255.0"
    var router = ""
    var probeIP = ""      // Adresse des Geräts, per Ping zum Testen (optional)
}

struct Detection { var ip: String; var mask: String }

// MARK: - Shell-Helfer

@discardableResult
func shell(_ path: String, _ args: [String]) -> (status: Int32, out: String) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = args
    let pipe = Pipe()
    p.standardOutput = pipe
    p.standardError = pipe
    do { try p.run() } catch { return (-1, "\(error)") }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return (p.terminationStatus, String(decoding: data, as: UTF8.self))
}

/// networksetup mit Admin-Rechten (setup.sh trägt sudo ohne Passwort dafür ein)
var lastNetsetupOutput = ""

func netsetup(_ args: [String]) -> Bool {
    let r = shell("/usr/bin/sudo", ["-n", "/usr/sbin/networksetup"] + args)
    lastNetsetupOutput = r.out.trimmingCharacters(in: .whitespacesAndNewlines)
    return r.status == 0 && !r.out.contains("Error")
}

func bg<T>(_ f: @escaping () -> T) async -> T {
    await withCheckedContinuation { c in
        DispatchQueue.global(qos: .userInitiated).async { c.resume(returning: f()) }
    }
}

func ipOf(_ dev: String) -> String? {
    let r = shell("/usr/sbin/ipconfig", ["getifaddr", dev])
    let s = r.out.trimmingCharacters(in: .whitespacesAndNewlines)
    return (r.status == 0 && !s.isEmpty) ? s : nil
}

func isLinkUp(_ dev: String) -> Bool {
    shell("/sbin/ifconfig", [dev]).out.contains("status: active")
}

func ping(_ ip: String) -> Bool {
    shell("/sbin/ping", ["-c", "2", "-t", "3", "-q", ip]).status == 0
}

// MARK: - Erkennung (passiv, aus tcpdump-Ausgabe)

func maskString(bits: Int) -> String {
    switch bits {
    case 8: return "255.0.0.0"
    case 16: return "255.255.0.0"
    default: return "255.255.255.0"
    }
}

/// Wertet ARP- und IP-Pakete aus und schätzt Geräte-IP und Netzmaske.
func analyze(_ text: String) -> Detection? {
    let arp = try! NSRegularExpression(pattern: #"who-has (\d+\.\d+\.\d+\.\d+).* tell (\d+\.\d+\.\d+\.\d+)"#)
    let ipp = try! NSRegularExpression(pattern: #"IP (\d+\.\d+\.\d+\.\d+)(?:\.\d+)? > (\d+\.\d+\.\d+\.\d+)"#)
    var counts: [String: Int] = [:]
    var bits: Int?

    for line in text.split(separator: "\n") {
        let s = String(line)
        let ns = s as NSString
        let r = NSRange(location: 0, length: ns.length)
        if let m = arp.firstMatch(in: s, range: r) {
            let target = ns.substring(with: m.range(at: 1))
            let sender = ns.substring(with: m.range(at: 2))
            // ARP-Probe: Absender 0.0.0.0, gesuchte Adresse ist die eigene des Geräts
            counts[sender == "0.0.0.0" ? target : sender, default: 0] += 1
        } else if let m = ipp.firstMatch(in: s, range: r) {
            let src = ns.substring(with: m.range(at: 1))
            let dst = ns.substring(with: m.range(at: 2))
            if src != "0.0.0.0" { counts[src, default: 0] += 1 }
            // Gerichteter Broadcast verrät die Netzmaske (z. B. 2.255.255.255 → /8)
            if dst != "255.255.255.255", let first = Int(dst.split(separator: ".")[0]), first < 224 {
                if dst.hasSuffix(".255.255.255") { bits = 8 }
                else if dst.hasSuffix(".255.255") { bits = 16 }
                else if dst.hasSuffix(".255") { bits = 24 }
            }
        }
    }
    guard let best = counts.max(by: { $0.value < $1.value })?.key else { return nil }
    let b = best.hasPrefix("169.254.") ? 16 : (bits ?? 24)
    return Detection(ip: best, mask: maskString(bits: b))
}

func ownAddress(for d: Detection) -> String {
    if d.ip.hasPrefix("169.254.") {
        return "169.254.\(Int.random(in: 1...254)).\(Int.random(in: 1...254))"
    }
    let o = d.ip.split(separator: ".").map(String.init)
    var last = 250
    while String(last) == o[3] { last -= 1 }
    return "\(o[0]).\(o[1]).\(o[2]).\(last)"
}

final class Buf {
    private let l = NSLock()
    private var s = ""
    func add(_ x: String) { l.lock(); s += x; l.unlock() }
    var text: String { l.lock(); defer { l.unlock() }; return s }
}

// MARK: - Engine

@MainActor
final class Engine: ObservableObject {
    @Published var ports: [Port] = []
    @Published var selected: String = UserDefaults.standard.string(forKey: "selected") ?? "" {
        didSet { UserDefaults.standard.set(selected, forKey: "selected"); wasUp = linkUp }
    }
    @Published var autoOn = false
    @Published var linkUp = false
    @Published var currentIP = "–"
    @Published var status = "Automatik aus"
    @Published var logLines: [String] = []
    @Published var listenSeconds: Int = max(3, UserDefaults.standard.integer(forKey: "listen")) {
        didSet { UserDefaults.standard.set(listenSeconds, forKey: "listen") }
    }
    @Published var profiles: [StaticProfile] = [] {
        didSet {
            if let d = try? JSONEncoder().encode(profiles) { UserDefaults.standard.set(d, forKey: "profiles") }
        }
    }

    private var timer: Timer?
    private var task: Task<Void, Never>?
    private var capture: Process?
    private var wasUp = false
    private let dhcpSeconds = 10

    init() {
        if let d = UserDefaults.standard.data(forKey: "profiles"),
           let p = try? JSONDecoder().decode([StaticProfile].self, from: d) { profiles = p }
        if listenSeconds < 3 { listenSeconds = 8 }
        refreshPorts()
        // Beim Beenden der App läuft garantiert nichts weiter
        NotificationCenter.default.addObserver(forName: NSApplication.willTerminateNotification,
                                               object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.cancel() }
        }
        timer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            Task { @MainActor in await self?.poll() }
        }
    }

    var currentPort: Port? { ports.first { $0.service == selected } }

    func log(_ s: String) {
        let t = DateFormatter(); t.dateFormat = "HH:mm:ss"
        logLines.append("\(t.string(from: Date()))  \(s)")
        if logLines.count > 200 { logLines.removeFirst(logLines.count - 200) }
    }

    func refreshPorts() {
        let out = shell("/usr/sbin/networksetup", ["-listnetworkserviceorder"]).out
        var result: [Port] = []
        var service: String?
        for raw in out.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("(Hardware Port:") {
                if let s = service, let r = line.range(of: "Device: ") {
                    let dev = line[r.upperBound...].trimmingCharacters(in: CharacterSet(charactersIn: ") "))
                    if !dev.isEmpty && !dev.contains("(") { result.append(Port(service: s, device: dev)) }
                }
                service = nil
            } else if line.hasPrefix("("), let close = line.firstIndex(of: ")") {
                service = String(line[line.index(after: close)...]).trimmingCharacters(in: .whitespaces)
            }
        }
        ports = result
        if currentPort == nil { selected = result.first?.service ?? "" }
    }

    // Reine Anzeige (nur lesen). Handeln tut die App nur, wenn die Automatik an ist.
    func poll() async {
        guard let port = currentPort else { return }
        let (up, ip) = await bg { (isLinkUp(port.device), ipOf(port.device)) }
        linkUp = up
        currentIP = ip ?? "–"
        if autoOn && up && !wasUp { runSequence() }
        if !up && wasUp {
            cancel()
            if autoOn { status = "Kein Kabel – warte auf Verbindung" }
        }
        wasUp = up
    }

    func setAuto(_ on: Bool) {
        autoOn = on
        wasUp = linkUp   // beim Einschalten nicht sofort etwas ändern
        if on { status = linkUp ? "Automatik an – wartet auf nächstes Anstecken" : "Automatik an – wartet auf Kabel" }
        else { cancel(); status = "Automatik aus – Einstellungen bleiben unverändert" }
        log(on ? "Automatik EIN" : "Automatik AUS")
    }

    func cancel() {
        task?.cancel(); task = nil
        capture?.terminate(); capture = nil
    }

    func runSequence() {
        guard let port = currentPort else { return }
        cancel()
        task = Task { await sequence(port) }
    }

    func resetToDHCP() {
        guard let port = currentPort else { return }
        cancel()
        let ok = netsetup(["-setdhcp", port.service])
        log(ok ? "Auf DHCP zurückgesetzt" : "Fehler bei networksetup: \(lastNetsetupOutput)")
        status = "DHCP"
    }

    // MARK: Ablauf

    func sequence(_ port: Port) async {
        let svc = port.service, dev = port.device
        log("Start für \(svc) (\(dev))")

        // 1) Passiv lauschen
        status = "Lausche am Kabel …"
        if !(await bg { netsetup(["-setv4off", svc]) }) {
            log("Fehler bei networksetup: \(lastNetsetupOutput)")
            status = "Fehler beim Umstellen – siehe Protokoll"
            return
        }
        let (det, err) = await listen(dev, seconds: listenSeconds)
        if Task.isCancelled { return }
        if !err.isEmpty { log(err) }
        if let d = det {
            let own = ownAddress(for: d)
            log("Gerät erkannt: \(d.ip), Maske \(d.mask) → eigene Adresse \(own)")
            if await applyStatic(svc, ip: own, mask: d.mask, router: "") {
                let ok = await bg { ping(d.ip) }
                status = "Statisch \(own) ↔ Gerät \(d.ip)" + (ok ? "" : " (Ping ohne Antwort)")
                return
            }
        } else {
            log("Kein Verkehr erkannt")
        }
        if Task.isCancelled { return }

        // 2) DHCP
        status = "Probiere DHCP …"
        _ = await bg { netsetup(["-setdhcp", svc]) }
        for _ in 0..<dhcpSeconds {
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            if Task.isCancelled { return }
            if let ip = await bg({ ipOf(dev) }), !ip.hasPrefix("169.254.") {
                log("DHCP-Adresse erhalten: \(ip)")
                status = "DHCP: \(ip)"
                return
            }
        }
        log("Kein DHCP-Server")

        // 3) Eigene Profile der Reihe nach
        for p in profiles {
            status = "Probiere Profil „\(p.name)“ …"
            _ = await applyStatic(svc, ip: p.ip, mask: p.mask, router: p.router)
            if Task.isCancelled { return }
            if p.probeIP.isEmpty {
                log("Profil „\(p.name)“ gesetzt (ohne Test)")
                status = "Profil „\(p.name)“: \(p.ip)"
                return
            }
            if await bg({ ping(p.probeIP) }) {
                log("Profil „\(p.name)“: \(p.probeIP) antwortet")
                status = "Profil „\(p.name)“: \(p.ip)"
                return
            }
            log("Profil „\(p.name)“: keine Antwort von \(p.probeIP)")
        }

        status = "Nichts hat funktioniert"
        log("Ende ohne Ergebnis")
    }

    func applyStatic(_ svc: String, ip: String, mask: String, router: String) async -> Bool {
        let ok: Bool = await bg {
            if !router.isEmpty { return netsetup(["-setmanual", svc, ip, mask, router]) }
            // Je nach macOS-Version wird ein Router verlangt → Fallback mit 0.0.0.0
            return netsetup(["-setmanual", svc, ip, mask]) || netsetup(["-setmanual", svc, ip, mask, "0.0.0.0"])
        }
        if !ok { log("Fehler beim Setzen von \(ip)") }
        try? await Task.sleep(nanoseconds: 1_500_000_000)
        return ok
    }

    func listen(_ dev: String, seconds: Int) async -> (Detection?, String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/sbin/tcpdump")
        p.arguments = ["-l", "-n", "-i", dev, "arp", "or", "ip"]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        let buf = Buf()
        pipe.fileHandleForReading.readabilityHandler = { h in
            buf.add(String(decoding: h.availableData, as: UTF8.self))
        }
        do { try p.run() } catch { return (nil, "tcpdump startet nicht: \(error)") }
        capture = p
        defer {
            pipe.fileHandleForReading.readabilityHandler = nil
            p.terminate()
            capture = nil
        }
        for i in 0..<(seconds * 2) {
            try? await Task.sleep(nanoseconds: 500_000_000)
            if Task.isCancelled { return (nil, "abgebrochen") }
            if i >= 5, let d = analyze(buf.text) { return (d, "") }
        }
        let t = buf.text
        if t.contains("Permission denied") || t.contains("/dev/bpf") {
            return (nil, "Keine Berechtigung zum Mitlesen – setup.sh ausführen und neu starten")
        }
        return (analyze(t), "")
    }
}
