import SwiftUI

struct ContentView: View {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var model = PhoneKeyModel()

    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                Image(systemName: "iphone.gen3.radiowaves.left.and.right")
                    .font(.system(size: 58))
                    .foregroundStyle(.tint)
                    .padding(.top, 40)

                Text("PhoneKey")
                    .font(.largeTitle.bold())
                Text("Approve Windows sign-in with this iPhone")
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)

                VStack(alignment: .leading, spacing: 12) {
                    Label(model.isAdvertising ? "Ready nearby" : "Bluetooth is off",
                          systemImage: model.isAdvertising ? "checkmark.circle.fill" : "antenna.radiowaves.left.and.right.slash")
                        .font(.headline)
                    Text(model.status)
                        .font(.body)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(20)
                .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 18))

                if let code = model.pairingCode {
                    VStack(spacing: 8) {
                        Text("Pairing code")
                            .font(.headline)
                        Text(code)
                            .font(.system(size: 38, weight: .bold, design: .monospaced))
                            .accessibilityLabel("Pairing code \(code)")
                        Text("Confirm only if Windows shows the same code")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(20)
                    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 18))
                }

                Button {
                    model.scanWindows()
                } label: {
                    Label("Scan Windows QR", systemImage: "qrcode.viewfinder")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                }
                .buttonStyle(.borderedProminent)

                Button(model.isAdvertising ? "Stop Bluetooth" : "Start Bluetooth") {
                    if model.isAdvertising { model.stopBluetooth() }
                    else { model.startBluetooth() }
                }
                .buttonStyle(.bordered)

                Spacer()
                Text("Keep PhoneKey open and the iPhone near Windows while signing in.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            .padding(.horizontal, 24)
            .navigationTitle("PhoneKey")
            .navigationBarTitleDisplayMode(.inline)
            .onAppear { model.startBluetooth() }
            .onChange(of: scenePhase) { _, phase in
                if phase == .active { model.startBluetooth() }
            }
            .sheet(isPresented: $model.showScanner, onDismiss: model.scannerDismissed) {
                NavigationStack {
                    PhoneKeyQRScanner(onScan: model.acceptQR, onError: model.scannerFailed)
                        .ignoresSafeArea(edges: .bottom)
                        .navigationTitle("Scan Windows QR")
                        .navigationBarTitleDisplayMode(.inline)
                        .toolbar {
                            ToolbarItem(placement: .topBarTrailing) {
                                Button("Cancel") { model.showScanner = false }
                            }
                        }
                }
            }
        }
    }
}
