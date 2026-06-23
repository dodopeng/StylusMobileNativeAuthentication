# iOS Example App

SwiftUI demo of the P256Account SDK: create a Secure Enclave key, point at a
deployed account + relayer, and sign/relay a test `execute` behind Face ID.

```bash
brew install xcodegen
cd sdk/ios/Example
xcodegen generate
open P256Example.xcodeproj
```

Run on a **physical device** — the Simulator has no Secure Enclave. Flow:

1. Tap **Create / load Secure Enclave key** → copy the shown `(x, y)` and deploy
   the account: `cargo stylus deploy --constructor-args <x> <y>`.
2. Enter the deployed account address, your RPC, and the relayer URL
   (`sdk/tooling` relayer).
3. Tap **Sign & relay test execute** → Face ID → the SDK signs the EIP-712
   digest, the relayer broadcasts, and the status shows the tx hash.
