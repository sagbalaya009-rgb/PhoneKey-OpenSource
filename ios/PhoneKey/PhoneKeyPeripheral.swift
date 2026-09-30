import CoreBluetooth
import Foundation

// Windows is the GATT central; the iPhone advertises the same three UUIDs as Android.
final class PhoneKeyPeripheral: NSObject, CBPeripheralManagerDelegate {
    static let serviceUUID = CBUUID(string: "7d2ea28a-f7bd-485a-bd9d-92ad6ecfe93e")
    static let challengeUUID = CBUUID(string: "7d2ea28b-f7bd-485a-bd9d-92ad6ecfe93e")
    static let proofUUID = CBUUID(string: "7d2ea28c-f7bd-485a-bd9d-92ad6ecfe93e")

    var onStatus: ((String) -> Void)?
    var onAdvertising: ((Bool) -> Void)?
    var onChallenge: ((PhoneKeyProtocol.Challenge) -> Void)?
    private var manager: CBPeripheralManager?
    private var published = false
    private var wantsAdvertising = false
    private var challengeBytes = Data()
    private var challengeCentral: UUID?
    private var proofBytes = Data()
    private var proofCentral: UUID?

    func start() {
        wantsAdvertising = true
        if manager == nil {
            manager = CBPeripheralManager(delegate: self, queue: .main)
        } else if manager?.state == .poweredOn {
            publishIfNeeded()
        }
    }

    func stop() {
        wantsAdvertising = false
        if manager?.state == .poweredOn {
            manager?.stopAdvertising()
            manager?.removeAllServices()
        }
        published = false
        clearProof()
        challengeBytes.removeAll()
        challengeCentral = nil
        onAdvertising?(false)
        onStatus?("Bluetooth stopped")
    }

    func setProof(_ proof: Data) throws {
        guard proof.count <= PhoneKeyCBOR.maximumSize, challengeCentral != nil else {
            throw PhoneKeyError.invalid("No active Windows Bluetooth request")
        }
        proofBytes = proof
        proofCentral = challengeCentral
        onStatus?("Approval ready for Windows")
    }

    func clearProof() {
        proofBytes.removeAll()
        proofCentral = nil
    }

    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        switch peripheral.state {
        case .poweredOn: publishIfNeeded()
        case .poweredOff:
            published = false
            onAdvertising?(false)
            onStatus?("Turn on Bluetooth to use PhoneKey")
        case .unauthorized:
            onAdvertising?(false)
            onStatus?("Allow Bluetooth access for PhoneKey in Settings")
        default:
            onAdvertising?(false)
            onStatus?("Bluetooth is not ready")
        }
    }

    private func publishIfNeeded() {
        guard wantsAdvertising, let manager, manager.state == .poweredOn else { return }
        if published {
            if !manager.isAdvertising {
                manager.startAdvertising([CBAdvertisementDataServiceUUIDsKey: [Self.serviceUUID]])
            }
            return
        }
        let challenge = CBMutableCharacteristic(type: Self.challengeUUID,
                                                 properties: [.write], value: nil,
                                                 permissions: [.writeable])
        let proof = CBMutableCharacteristic(type: Self.proofUUID,
                                             properties: [.read, .notify], value: nil,
                                             permissions: [.readable])
        let service = CBMutableService(type: Self.serviceUUID, primary: true)
        service.characteristics = [challenge, proof]
        published = true
        manager.add(service)
        onStatus?("Preparing iPhone Bluetooth service")
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didAdd service: CBService, error: Error?) {
        guard service.uuid == Self.serviceUUID else { return }
        guard error == nil, wantsAdvertising else {
            published = false
            onStatus?("Bluetooth service failed: \(error?.localizedDescription ?? "stopped")")
            return
        }
        peripheral.startAdvertising([CBAdvertisementDataServiceUUIDsKey: [Self.serviceUUID]])
    }

    func peripheralManagerDidStartAdvertising(_ peripheral: CBPeripheralManager, error: Error?) {
        onAdvertising?(error == nil && peripheral.isAdvertising)
        onStatus?(error.map { "Bluetooth advertising failed: \($0.localizedDescription)" } ??
                  "iPhone is advertising to Windows")
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
        for request in requests {
            guard request.characteristic.uuid == Self.challengeUUID, let value = request.value else {
                peripheral.respond(to: request, withResult: .writeNotPermitted)
                continue
            }
            if request.offset == 0 {
                challengeBytes.removeAll()
                challengeCentral = request.central.identifier
                clearProof()
            }
            guard challengeCentral == request.central.identifier,
                  request.offset == challengeBytes.count,
                  challengeBytes.count + value.count <= PhoneKeyCBOR.maximumSize else {
                challengeBytes.removeAll()
                challengeCentral = nil
                peripheral.respond(to: request, withResult: .invalidOffset)
                continue
            }
            challengeBytes.append(value)
            peripheral.respond(to: request, withResult: .success)
            do {
                let challenge = try PhoneKeyProtocol.decodeChallenge(challengeBytes)
                challengeBytes.removeAll()
                onChallenge?(challenge)
            } catch PhoneKeyError.truncated {
                // Windows may send one GATT prepared write in several pieces.
            } catch {
                challengeBytes.removeAll()
                challengeCentral = nil
                onStatus?("Rejected Windows request: \(error.localizedDescription)")
            }
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveRead request: CBATTRequest) {
        guard request.characteristic.uuid == Self.proofUUID,
              proofCentral == request.central.identifier, !proofBytes.isEmpty else {
            peripheral.respond(to: request, withResult: .readNotPermitted)
            return
        }
        guard request.offset <= proofBytes.count else {
            peripheral.respond(to: request, withResult: .invalidOffset)
            return
        }
        request.value = proofBytes.subdata(in: request.offset..<proofBytes.count)
        peripheral.respond(to: request, withResult: .success)
        onStatus?("Approval sent to Windows")
    }
}
