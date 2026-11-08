import SwiftUI

@main
struct NetAutoApp: App {
    var body: some Scene {
        WindowGroup("NetAuto") {
            ContentView()
                .frame(minWidth: 620, minHeight: 600)
        }
    }
}

struct ContentView: View {
    @StateObject private var e = Engine()

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {

            HStack {
                Picker("Adapter", selection: $e.selected) {
                    ForEach(e.ports) { Text("\($0.service) (\($0.device))").tag($0.service) }
                }
                Button { e.refreshPorts() } label: { Image(systemName: "arrow.clockwise") }
            }

            HStack(spacing: 8) {
                Circle().fill(e.linkUp ? Color.green : Color.gray).frame(width: 10, height: 10)
                Text(e.linkUp ? "Kabel verbunden" : "Kein Kabel")
                Spacer()
                Text("Aktuelle IP: \(e.currentIP)").monospacedDigit()
            }

            Toggle("Automatik aktiv", isOn: Binding(get: { e.autoOn }, set: { e.setAuto($0) }))
                .toggleStyle(.switch)
                .font(.headline)

            Text(e.status).font(.callout).foregroundStyle(.secondary)

            Stepper("Lauschzeit: \(e.listenSeconds) s", value: $e.listenSeconds, in: 3...30)

            GroupBox("Feste Profile – werden der Reihe nach probiert, wenn Erkennung und DHCP scheitern") {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach($e.profiles) { $p in
                        HStack {
                            TextField("Name", text: $p.name).frame(width: 90)
                            TextField("IP", text: $p.ip)
                            TextField("Maske", text: $p.mask)
                            TextField("Router", text: $p.router)
                            TextField("Test-IP", text: $p.probeIP)
                            Button(role: .destructive) {
                                e.profiles.removeAll { $0.id == p.id }
                            } label: { Image(systemName: "minus.circle") }
                                .buttonStyle(.borderless)
                        }
                    }
                    Button("Profil hinzufügen") { e.profiles.append(StaticProfile()) }
                }
                .padding(6)
            }

            HStack {
                Button("Jetzt konfigurieren") { e.runSequence() }
                    .disabled(e.currentPort == nil)
                Button("Auf DHCP zurücksetzen") { e.resetToDHCP() }
            }

            GroupBox("Protokoll") {
                ScrollView {
                    Text(e.logLines.joined(separator: "\n"))
                        .font(.system(.caption, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                }
                .frame(minHeight: 120)
            }
        }
        .padding(16)
    }
}
