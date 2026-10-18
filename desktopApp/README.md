# desktopApp — **Cruciform** for the desktop

Cruciform on a Linux desktop (Compose Multiplatform, JVM). It holds **this computer's
device**, the one in void-which-binds-go's per-user device directory
(`$XDG_CONFIG_HOME/void-which-binds/device`, or `VOID_WHICH_BINDS_DEVICE_DIR`), whose keys
are in a passphrase-sealed file (ADR-0010). The reference CLI and heyarr use the same
directory, so they and this app share one device.

**Not hardware-backed.** A copy of the sealed file is useless without the passphrase, but
software running as you can capture the passphrase or read the keys while they are
unlocked. Every screen says so.

| Screen | What it does |
|---|---|
| This device | Name, device key, the identity's fingerprint; lock or unlock |
| Devices | The identity's members; remove one (this device signs the remove) |
| Add a device | This device is the initiator: a QR for the new device, then the security code to compare before anything is signed |
| Sign in | Approve a web sign-in from a `void-which-binds:login?…` link (pasted, or opened with the app), number matching included |
| Approvals | Fetch an ADR-0019 action approval from the configured brokers and show it. Answering is not possible from the desktop yet: no endpoint for answers is defined |
| Settings | The pairing relay, the sites told of device changes, the approval brokers. Nothing is built in |

The passphrase is asked for in the app (never echoed, never on the clipboard) and held
for 10 minutes, then wiped. The app does not create or enrol a device: do that with the
void-which-binds CLI, or from a phone.

```sh
./gradlew :desktopApp:run                    # run it
./gradlew :desktopApp:test                   # the engine's tests, over Go's device-dir vector
./gradlew :desktopApp:createDistributable   # a self-contained app image (its own runtime)
```
