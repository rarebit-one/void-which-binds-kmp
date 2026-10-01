import Foundation
import Security
import VoidWhichBinds

/// The iOS mirror of the Android `DeviceVoidbindEngine`: it ties the commonMain
/// brain to the platform — the Secure-Enclave-sealed device signing key
/// (`DeviceKeyStore`), a persisted X25519 encryption keypair, `UserIdentity`
/// create/restore, `Enrolment`, and the three flow coordinators over a
/// `URLSessionHttpTransport`. The SwiftUI ViewModels call this off the main thread.
///
/// Deliberately thin: all identity crypto + wire lives in the KMP library; this is
/// only provisioning + wiring, the same split the Android engine keeps.
///
/// > Type-checked against the exported `VoidWhichBinds.xcframework`; the Secure Enclave /
/// > biometric paths need a **real device** (docs/DEVICE-TESTING.md).
public final class VoidbindEngine {

    public static let deviceAlias = "device"
    private let transport: HttpTransport

    /// Call once at app startup: inject the Swift Secure Enclave sealer, then build.
    public init(sealer: SecureEnclaveSealer = EnclaveSealer(),
                transport: HttpTransport = URLSessionHttpTransport()) {
        VoidbindIos.shared.doInit(sealer: sealer)
        self.transport = transport
    }

    // MARK: - Identity (onboarding)

    /// Mint a brand-new identity. Show `identity.recovery.format()` to the user ONCE.
    public func createIdentity() -> UserIdentity {
        UserIdentity.companion.create()
    }

    /// Restore from the written-down recovery secret. Throws (Kotlin
    /// `IllegalArgumentException`) on a mistyped secret — surface it as "check the secret".
    public func restoreIdentity(_ secret: String) throws -> UserIdentity {
        try UserIdentity.companion.restore(secret: secret)
    }

    // MARK: - Device identity (hardware sign key + sealed enc key)

    /// Provision (or load) this device's key material: the Secure-Enclave-sealed
    /// Ed25519 signing key + a persisted X25519 encryption keypair.
    public func deviceIdentity() -> DeviceIdentity {
        let store = DeviceKeyStore.companion.getOrCreate(alias: Self.deviceAlias)
        let enc = loadOrCreateEncryptionKey()
        return DeviceIdentity(
            signPublicKey: store.publicKey().bytes,
            encPublicKey: enc.publicKey,
            encPrivateKey: enc.privateKey,
            signFn: { message in store.sign(message: message) }
        )
    }

    /// Self-sign the first device's enrolment cert (bootstrap: user + device on one phone).
    public func enrolFirstDevice(identity: UserIdentity, device: DeviceIdentity) -> String {
        Enrolment.shared.selfEnrol(
            identity: identity,
            device: device,
            issuedAt: Self.now(),
            lifetimeSeconds: Enrolment.shared.DEFAULT_LIFETIME_SECONDS
        )
    }

    // MARK: - Coordinators (the ViewModels drive begin → SAS/audience → confirm)

    public func loginApproval(cert: String, device: DeviceIdentity) -> LoginApproval {
        LoginApproval(http: transport, device: device, enrolmentCert: cert)
    }

    public func devicePairing(device: DeviceIdentity) -> DevicePairing {
        DevicePairing(http: transport, device: device, pollIntervalMillis: 150)
    }

    public func deviceAuthorization(identity: UserIdentity) -> DeviceAuthorization {
        DeviceAuthorization(
            http: transport,
            identity: identity,
            clock: { KotlinLong(longLong: Self.now()) },
            certLifetimeSeconds: Enrolment.shared.DEFAULT_LIFETIME_SECONDS,
            pollIntervalMillis: 150
        )
    }

    /// Classify a scanned QR (login vs pairing) for the Scan screen's `switch`.
    public func parseScanned(_ uri: String) -> VoidbindQr {
        VoidbindQr.companion.parse(uri: uri)
    }

    // MARK: - Convenience builders (provision the SE device key, then build)

    /// Build a login-approval coordinator. Provisions the device key (biometric).
    public func makeLoginApproval(cert: String) -> LoginApproval {
        loginApproval(cert: cert, device: deviceIdentity())
    }

    /// Build the pairing (responder) coordinator for a new device joining an account.
    public func makeDevicePairing() -> DevicePairing {
        devicePairing(device: deviceIdentity())
    }

    /// Build the authorising (initiator) coordinator; needs the user identity (recovery secret).
    public func makeDeviceAuthorization(identity: UserIdentity) -> DeviceAuthorization {
        deviceAuthorization(identity: identity)
    }

    // MARK: - X25519 encryption keypair persistence (Keychain, this-device-only)

    private func loadOrCreateEncryptionKey() -> DeviceIdentity.EncryptionKey {
        if let priv = keychainRead("void-which-binds.\(Self.deviceAlias).encpriv"),
           let pub = keychainRead("void-which-binds.\(Self.deviceAlias).encpub") {
            return DeviceIdentity.EncryptionKey(
                privateKey: priv.toKotlinByteArray(),
                publicKey: pub.toKotlinByteArray()
            )
        }
        let fresh = DeviceIdentity.companion.generateEncryptionKey()
        // Hardening follow-up: seal `encpriv` under the SE key via EnclaveSealer,
        // matching the Android AES-GCM wrap. Baseline here is device-only Keychain.
        keychainWrite("void-which-binds.\(Self.deviceAlias).encpriv", fresh.privateKey.toData())
        keychainWrite("void-which-binds.\(Self.deviceAlias).encpub", fresh.publicKey.toData())
        return fresh
    }

    private func keychainWrite(_ account: String, _ data: Data) {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "one.rarebit.voidwhichbinds",
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(base as CFDictionary)
        var add = base
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(add as CFDictionary, nil)
    }

    private func keychainRead(_ account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "one.rarebit.voidwhichbinds",
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
        ]
        var item: CFTypeRef?
        return SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess ? item as? Data : nil
    }

    private static func now() -> Int64 { Int64(Date().timeIntervalSince1970) }
}
