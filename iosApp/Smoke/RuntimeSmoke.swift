import Foundation
import VoidWhichBinds

// A RUNTIME smoke of the Swift <-> KMP bridge through the exported
// `VoidWhichBinds.xcframework` — it runs the actual identity path from Swift and checks
// the results, so it proves the ObjC bridging (Data <-> KotlinByteArray, the
// companion/object accessors, @Throws) works at runtime, not just that the Swift
// type-checks. It exercises ONLY the pure/derivation surface, so it needs no
// Secure Enclave, no network, and no UI — it runs in the iOS Simulator.
//
// Run it (from the repo root):
//
//   ./gradlew assembleVoidWhichBindsDebugXCFramework
//   SLICE=$PWD/build/XCFrameworks/debug/VoidWhichBinds.xcframework/ios-arm64-simulator
//   xcrun --sdk iphonesimulator swiftc -target arm64-apple-ios17.0-simulator \
//     -F "$SLICE" -Xlinker -rpath -Xlinker "$SLICE" iosApp/Smoke/RuntimeSmoke.swift -o /tmp/vbsmoke
//   DEV=$(xcrun simctl list devices available | grep -m1 -oE '\([0-9A-F-]{36}\)' | tr -d '()')
//   xcrun simctl boot "$DEV"; xcrun simctl spawn "$DEV" /tmp/vbsmoke
//
// Expected: every line ends OK and the last line is SMOKE_DONE. Verified passing
// on iOS 26.2 Simulator (arm64).

private func hex(_ a: KotlinByteArray) -> String {
    var d = Data(count: Int(a.size))
    for i in 0..<Int(a.size) { d[i] = UInt8(bitPattern: a.get(index: Int32(i))) }
    return d.map { String(format: "%02x", $0) }.joined()
}

// 1. create -> recovery secret -> restore round-trips to the SAME identity.
let id = UserIdentity.companion.create()
let restored = try! UserIdentity.companion.restore(secret: id.recovery.format())
print("ROUNDTRIP \(hex(id.userPublicKey) == hex(restored.userPublicKey) ? "OK" : "MISMATCH")")

// 2. a known recovery secret derives the exact void-which-binds-go public key — proves
//    HKDF + the pure-Kotlin Ed25519 pub-from-seed run correctly THROUGH Swift. The
//    secret and key are the Go-pinned `vectors/recovery/counting-entropy.json`.
let kat = try! UserIdentity.companion.restore(
    secret: "void-which-binds1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0stska6c")
print("KAT \(hex(kat.userPublicKey) == "da16ead22f9bd99facafa8013a997aff28dba13887c7aa1e77b2e88214dff6a6" ? "OK" : "FAIL")")

// 3. a mistyped secret THROWS (catchable), not crash — the @Throws fix, at runtime.
do {
    _ = try UserIdentity.companion.restore(secret: "void-which-binds1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
    print("THROWS FAIL(no throw)")
} catch {
    print("THROWS OK")
}

// 3b. a valid gen1 (`heyarr1…`) secret THROWS too: gen2 has no gen1 reader (ADR-0022).
do {
    _ = try UserIdentity.companion.restore(
        secret: "heyarr1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s6e0ucu")
    print("GEN1_REFUSED FAIL(no throw)")
} catch {
    print("GEN1_REFUSED OK")
}

// 4. the web-login QR wire round-trips byte-identically through Swift.
let qr = LoginQr.shared.encode(rp: "https://homelab.example:8443/app", id: "L1a2b3")
print("QR_MATCH \(qr == "void-which-binds:login?id=L1a2b3&rp=https%3A%2F%2Fhomelab.example%3A8443%2Fapp" ? "OK" : "FAIL")")

print("SMOKE_DONE")
