import Combine
import Foundation
import LocalAuthentication

@MainActor
final class PhoneKeyModel: ObservableObject {
    @Published private(set) var status = "Open PhoneKey before scanning Windows"
    @Published private(set) var pairingCode: String?
    @Published private(set) var isAdvertising = false
    @Published var showScanner = false

    private let peripheral = PhoneKeyPeripheral()
    private let identity = PhoneKeyIdentityStore()
    private var scannedQR: PhoneKeyBootstrap?
    private var earlyLogin: PhoneKeyProtocol.Login?
    private var pendingEnrollment: PhoneKeyProtocol.Enrollment?
    private var scannerIsDismissing = false
    private var approvalInFlight = false

    init() {
        peripheral.onStatus = { [weak self] message in
            Task { @MainActor in self?.status = message }
        }
        peripheral.onAdvertising = { [weak self] active in
            Task { @MainActor in self?.isAdvertising = active }
        }
        peripheral.onChallenge = { [weak self] challenge in
            Task { @MainActor in self?.handle(challenge) }
        }
    }

    func startBluetooth() {
        peripheral.start()
    }

    func stopBluetooth() {
        peripheral.stop()
        scannedQR = nil
        earlyLogin = nil
        pairingCode = nil
    }

    func scanWindows() {
        pairingCode = nil
        scannedQR = nil
        peripheral.clearProof()
        startBluetooth()
        scannerIsDismissing = false
        showScanner = true
        status = "Scan the fresh Windows QR"
    }

    func acceptQR(_ text: String) {
        scannerIsDismissing = true
        showScanner = false
        do {
            let qr = try PhoneKeyBootstrap(qr: text)
            scannedQR = qr
            status = "Windows QR accepted; waiting for its Bluetooth request"
        } catch {
            scannedQR = nil
            earlyLogin = nil
            status = error.localizedDescription
        }
    }

    func scannerFailed(_ message: String) {
        scannerIsDismissing = true
        showScanner = false
        scannedQR = nil
        status = message
    }

    func scannerDismissed() {
        scannerIsDismissing = false
        if let pendingEnrollment {
            self.pendingEnrollment = nil
            approveEnrollment(pendingEnrollment)
        } else if scannedQR != nil, let earlyLogin {
            self.earlyLogin = nil
            acceptLogin(earlyLogin)
        }
    }

    private func handle(_ challenge: PhoneKeyProtocol.Challenge) {
        guard !approvalInFlight else { return }
        pairingCode = nil
        peripheral.clearProof()
        switch challenge {
        case .login(let login):
            guard scannedQR != nil, !scannerIsDismissing else {
                earlyLogin = login
                status = scannedQR == nil
                    ? "Windows request received; scan its live QR"
                    : "Windows request received; preparing phone approval"
                return
            }
            acceptLogin(login)
        case .enrollment(let enrollment):
            scannedQR = nil
            earlyLogin = nil
            if showScanner || scannerIsDismissing {
                pendingEnrollment = enrollment
                scannerIsDismissing = true
                showScanner = false
            } else {
                approveEnrollment(enrollment)
            }
        }
    }

    private func acceptLogin(_ challenge: PhoneKeyProtocol.Login) {
        guard let qr = scannedQR,
              qr.windowsDeviceID == challenge.windowsDeviceID,
              qr.sessionID == challenge.sessionID,
              qr.expiresAtMS == challenge.expiresAtMS else {
            scannedQR = nil
            status = "Bluetooth request does not match the scanned Windows QR"
            return
        }
        guard identity.exists() else {
            scannedQR = nil
            status = "Enroll this iPhone with Windows first"
            return
        }
        approvalInFlight = true
        status = "Approve Windows sign-in with Face ID or your iPhone passcode"
        authenticate(reason: "Approve this Windows sign-in") { [weak self] context in
            guard let self else { return }
            defer {
                self.approvalInFlight = false
                self.scannedQR = nil
                context.invalidate()
            }
            do {
                guard PhoneKeyProtocol.nowMS() < challenge.expiresAtMS else {
                    throw PhoneKeyError.invalid("Windows QR expired before approval")
                }
                let device = try self.identity.identity(context: context)
                let transcript = try PhoneKeyProtocol.loginTranscript(challenge)
                let signature = try self.identity.sign(transcript, context: context)
                let proof = try PhoneKeyProtocol.loginProof(
                    deviceID: device.deviceID, sessionID: challenge.sessionID, signature: signature
                )
                try self.peripheral.setProof(proof)
                self.status = "Approved. Sending proof to Windows"
            } catch {
                self.peripheral.clearProof()
                self.status = "Sign-in approval failed: \(error.localizedDescription)"
            }
        }
    }

    private func approveEnrollment(_ challenge: PhoneKeyProtocol.Enrollment) {
        approvalInFlight = true
        status = "Windows wants to pair this iPhone. Approve on your phone"
        authenticate(reason: "Enroll this iPhone with PhoneKey for Windows") { [weak self] context in
            guard let self else { return }
            defer {
                self.approvalInFlight = false
                context.invalidate()
            }
            do {
                guard PhoneKeyProtocol.nowMS() < challenge.expiresAtMS else {
                    throw PhoneKeyError.invalid("Windows pairing request expired")
                }
                let device = try self.identity.createIfNeeded(context: context)
                let transcript = try PhoneKeyProtocol.enrollmentTranscript(
                    challenge, deviceID: device.deviceID, publicKey: device.publicKey
                )
                let signature = try self.identity.sign(transcript, context: context)
                let proof = try PhoneKeyProtocol.enrollmentProof(
                    deviceID: device.deviceID, enrollmentID: challenge.enrollmentID,
                    publicKey: device.publicKey, signature: signature
                )
                try self.peripheral.setProof(proof)
                self.pairingCode = try PhoneKeyProtocol.pairingCode(challenge: challenge, proof: proof)
                self.status = "Compare this code with Windows before confirming there"
            } catch {
                self.peripheral.clearProof()
                self.pairingCode = nil
                self.status = "Pairing failed: \(error.localizedDescription)"
            }
        }
    }

    private func authenticate(reason: String, completion: @escaping @MainActor (LAContext) -> Void) {
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            approvalInFlight = false
            status = error?.localizedDescription ?? "Set a passcode or Face ID on this iPhone"
            return
        }
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { [weak self] approved, error in
            Task { @MainActor in
                guard let self else { return }
                if approved {
                    completion(context)
                } else {
                    self.approvalInFlight = false
                    self.peripheral.clearProof()
                    self.status = error?.localizedDescription ?? "Phone approval cancelled"
                    context.invalidate()
                }
            }
        }
    }
}
