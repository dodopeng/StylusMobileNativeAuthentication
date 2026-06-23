# Android Example App

Demo of the P256Account SDK: create a StrongBox/TEE key, point at a deployed
account + relayer, and sign/relay a test `execute` behind a biometric.

```bash
cd sdk/android
./gradlew :example:installDebug   # or open in Android Studio and Run
```

Run on a **device with a biometric enrolled** (StrongBox needs real hardware;
the SDK falls back to the TEE otherwise). Flow:

1. **Create / load hardware key** → copy the shown `(x, y)` and deploy the
   account: `cargo stylus deploy --constructor-args <x> <y>`.
2. Enter the deployed account address. The relayer URL defaults to
   `http://10.0.2.2:8080/relay` (the emulator's alias for the host's
   `localhost`, where the `sdk/tooling` relayer runs).
3. **Sign & relay test execute** → biometric → the SDK signs and the relayer
   broadcasts; the status shows the tx hash.
