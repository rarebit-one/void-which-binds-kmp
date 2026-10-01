import CryptoKit
import Foundation
import LocalAuthentication
import Security
import VoidWhichBinds

/// The Swift implementation of the Kotlin `SecureEnclaveSealer` protocol the iOS
/// `DeviceKeyStore` needs (see the interface doc in commonMain). The device's
/// Ed25519 signing seed is software (CryptoKit can't put Ed25519 in the Enclave),
/// so it is **sealed at rest by a non-extractable Secure-Enclave P-256 key** via
/// ECIES; unsealing triggers the Enclave + a biometric gate. The seed lives in
/// memory only transiently while the Kotlin `DeviceKeyStore.sign` uses it, then is
/// zeroized on the Kotlin side.
///
/// Named `EnclaveSealer` (not `SecureEnclaveSealer`) because the latter is the
/// Kotlin protocol this conforms to.
///
/// Storage layout (all in the Keychain, per `alias`):
///  - the SE P-256 private key — a `SecKey` with `kSecAttrTokenIDSecureEnclave`,
///    access control `.privateKeyUsage` + `.biometryCurrentSet`, application tag
///    `voidbind.<alias>.sekey`. Non-extractable by construction.
///  - the sealed seed ciphertext — a generic-password item `voidbind.<alias>.sealed`.
///  - the Ed25519 public key (RAW 32 bytes, not secret) — `voidbind.<alias>.pub`.
///
/// > Type-checked against the exported `VoidWhichBinds.xcframework` (simulator slice);
/// > the Secure Enclave + biometric behaviour still needs a **real iPhone** (see
/// > docs/DEVICE-TESTING.md).
public final class EnclaveSealer: NSObject, SecureEnclaveSealer {

    private let eciesAlgorithm: SecKeyAlgorithm = .eciesEncryptionCofactorX963SHA256AESGCM
    private let reason: String

    /// - Parameter reason: the string shown in the biometric prompt on unseal.
    public init(reason: String = "Authenticate to use your Cruciform device key") {
        self.reason = reason
    }

    // MARK: - SecureEnclaveSealer

    public func sealExists(alias: String) -> Bool {
        (try? loadSealedCiphertext(alias)) != nil && (try? loadSecureEnclaveKey(alias)) != nil
    }

    public func loadPublicKey(alias: String) -> KotlinByteArray {
        guard let pub = try? loadPersisted(tag: pubTag(alias)) else {
            fatalError("EnclaveSealer: no public key for alias '\(alias)' — provision first")
        }
        return pub.toKotlinByteArray()
    }

    public func provision(
        alias: String,
        ed25519PublicKey: KotlinByteArray,
        ed25519Seed: KotlinByteArray
    ) {
        do {
            let seKey = try createSecureEnclaveKey(alias)
            guard let sePub = SecKeyCopyPublicKey(seKey) else {
                throw SealerError.publicKeyUnavailable
            }
            guard SecKeyIsAlgorithmSupported(sePub, .encrypt, eciesAlgorithm) else {
                throw SealerError.algorithmUnsupported
            }
            var seedData = ed25519Seed.toData()
            defer { seedData.resetBytes(in: 0..<seedData.count) }

            var cfError: Unmanaged<CFError>?
            guard let ciphertext = SecKeyCreateEncryptedData(
                sePub, eciesAlgorithm, seedData as CFData, &cfError
            ) as Data? else {
                throw (cfError?.takeRetainedValue()).map { SealerError.underlying($0) } ?? SealerError.sealFailed
            }
            try persist(ciphertext, tag: sealedTag(alias))
            try persist(ed25519PublicKey.toData(), tag: pubTag(alias))
        } catch {
            fatalError("EnclaveSealer.provision('\(alias)') failed: \(error)")
        }
    }

    public func unsealSeed(alias: String) -> KotlinByteArray {
        do {
            let seKey = try loadSecureEnclaveKey(alias) // triggers the Enclave + biometric on use
            let ciphertext = try loadSealedCiphertext(alias)
            var cfError: Unmanaged<CFError>?
            guard var seed = SecKeyCreateDecryptedData(
                seKey, eciesAlgorithm, ciphertext as CFData, &cfError
            ) as Data? else {
                throw (cfError?.takeRetainedValue()).map { SealerError.underlying($0) } ?? SealerError.unsealFailed
            }
            // Copy the seed out to Kotlin, then wipe our transient copy. The Kotlin
            // caller (DeviceKeyStore.sign) zeroizes its copy after signing.
            let out = seed.toKotlinByteArray()
            seed.resetBytes(in: 0..<seed.count)
            return out
        } catch {
            fatalError("EnclaveSealer.unsealSeed('\(alias)') failed: \(error)")
        }
    }

    // MARK: - Secure Enclave key

    private func createSecureEnclaveKey(_ alias: String) throws -> SecKey {
        var acError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &acError
        ) else {
            throw (acError?.takeRetainedValue()).map { SealerError.underlying($0) } ?? SealerError.accessControlFailed
        }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: seKeyTag(alias),
                kSecAttrAccessControl as String: access,
            ],
        ]
        var cfError: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &cfError) else {
            throw (cfError?.takeRetainedValue()).map { SealerError.underlying($0) } ?? SealerError.keyCreateFailed
        }
        return key
    }

    private func loadSecureEnclaveKey(_ alias: String) throws -> SecKey {
        let context = LAContext()
        context.localizedReason = reason
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: seKeyTag(alias),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: context,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let ref = item else {
            throw SealerError.keychain(status)
        }
        // SecItemCopyMatching returns a SecKey for kSecClassKey.
        return (ref as! SecKey)
    }

    // MARK: - Keychain persistence (ciphertext + public key)

    private func persist(_ data: Data, tag: String) throws {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "one.rarebit.voidbind",
            kSecAttrAccount as String: tag,
        ]
        SecItemDelete(base as CFDictionary)
        var add = base
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw SealerError.keychain(status) }
    }

    private func loadPersisted(tag: String) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "one.rarebit.voidbind",
            kSecAttrAccount as String: tag,
            kSecReturnData as String: true,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else {
            throw SealerError.keychain(status)
        }
        return data
    }

    private func loadSealedCiphertext(_ alias: String) throws -> Data { try loadPersisted(tag: sealedTag(alias)) }

    // MARK: - Tags

    private func seKeyTag(_ alias: String) -> Data { "voidbind.\(alias).sekey".data(using: .utf8)! }
    private func sealedTag(_ alias: String) -> String { "voidbind.\(alias).sealed" }
    private func pubTag(_ alias: String) -> String { "voidbind.\(alias).pub" }

    enum SealerError: Error {
        case publicKeyUnavailable, algorithmUnsupported, sealFailed, unsealFailed
        case accessControlFailed, keyCreateFailed
        case keychain(OSStatus)
        case underlying(CFError)
    }
}

// MARK: - Data ↔ KotlinByteArray bridging

extension Data {
    /// Copy into a fresh `KotlinByteArray` (values are signed 8-bit, matching Kotlin `Byte`).
    func toKotlinByteArray() -> KotlinByteArray {
        let out = KotlinByteArray(size: Int32(count))
        for (i, b) in enumerated() {
            out.set(index: Int32(i), value: Int8(bitPattern: b))
        }
        return out
    }
}

extension KotlinByteArray {
    /// Copy out into `Data` (reinterpreting each signed Kotlin `Byte` as an unsigned octet).
    func toData() -> Data {
        var data = Data(count: Int(size))
        for i in 0..<Int(size) {
            data[i] = UInt8(bitPattern: get(index: Int32(i)))
        }
        return data
    }
}
