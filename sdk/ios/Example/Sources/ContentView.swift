import SwiftUI
import P256Account

/// Minimal end-to-end demo of the P256Account SDK:
///   1. create / load a Secure Enclave P-256 key;
///   2. point at a deployed account + relayer;
///   3. sign a test `execute` behind Face ID and relay it.
///
/// The (x, y) shown in step 1 are the constructor args used to deploy the
/// account contract — `cargo stylus deploy --constructor-args <x> <y>`.
/// Run on a physical device; the Simulator has no Secure Enclave.
struct ContentView: View {
    @State private var pubKey = "—"
    @State private var rpc = "https://sepolia-rollup.arbitrum.io/rpc"
    // NOTE: `localhost` is the PHONE, not your Mac. On a physical device
    // (required — the Simulator has no Secure Enclave) point this at your
    // machine's LAN address, e.g. http://192.168.1.20:8080/relay, and keep the
    // ATS exception in project.yml. Prefer https in anything shipped.
    @State private var relayURL = "http://localhost:8080/relay"
    @State private var account = ""
    @State private var status = "idle"

    /// A plain, un-owned address. A 0-wei call with empty data to a non-contract
    /// always succeeds, which is what makes it a good connectivity probe.
    private let burnAddress = "0x000000000000000000000000000000000000dEaD"

    // Secure Enclave on a real device; a software key on the Simulator (which
    // has no enclave) so the demo still runs. Both are SignProviders.
    #if targetEnvironment(simulator)
    private let signer: SignProvider = (try? SoftwareP256Signer())!
    #else
    private let signer: SignProvider = SecureEnclaveSigner(tag: "xyz.heavenlydev.p256example", requireBiometric: true)
    #endif

    var body: some View {
        NavigationStack {
            Form {
                Section("1 · Hardware key") {
                    Button("Create / load Secure Enclave key", action: createOrLoadKey)
                    Text(pubKey).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                }
                Section("2 · Target") {
                    TextField("RPC URL", text: $rpc).autocorrectionDisabled()
                    TextField("Relayer URL", text: $relayURL).autocorrectionDisabled()
                    TextField("Account address (0x…)", text: $account).autocorrectionDisabled()
                }
                Section {
                    Button("Sign & relay test execute (Face ID)") { Task { await sendTestExecute() } }
                    Text("status: \(status)").font(.system(.caption, design: .monospaced))
                }
            }
            .navigationTitle("P256 Account")
        }
    }

    private func createOrLoadKey() {
        do {
            // The enclave signer needs an explicit create(); the software signer
            // generates its key on init, so publicKey() is enough.
            let pub: PublicKeyP256
            if let enclave = signer as? SecureEnclaveSigner {
                pub = enclave.exists() ? try enclave.publicKey() : try enclave.create()
            } else {
                pub = try signer.publicKey()
            }
            let x = Hex.toString([UInt8](pub.x.data))
            let y = Hex.toString([UInt8](pub.y.data))
            pubKey = "x = \(x)\ny = \(y)"
        } catch {
            pubKey = "key error: \(error)"
        }
    }

    private func sendTestExecute() async {
        guard account.count == 42 else { status = "enter a deployed account address first"; return }
        status = "signing…"
        let rpcClient = JSONRPCClient(endpoint: rpc)
        let relay = HTTPRelay(url: relayURL)
        let client = P256AccountClient(address: account, rpc: rpcClient, relay: relay, signer: signer)
        do {
            // 0 wei, empty data, to a plain address — exercises the full
            // sign → relay → on-chain path without touching real funds.
            //
            // NOT a self-call: `execute(Call(to: account))` re-enters the
            // account, which the re-entrancy guard rejects, so the demo would
            // always fail internally while still returning a tx hash.
            let txHash = try await client.execute(Call(to: burnAddress))
            status = "relayed, waiting for receipt…\n\(txHash)"

            // A tx hash does NOT mean the action succeeded: `execute` records a
            // failed inner call in the Executed event and still consumes the
            // nonce. Decode it before claiming success.
            let result = try await client.awaitExecuted(txHash: txHash)
            if result.success {
                status = "executed ✓\n\(txHash)"
            } else {
                let revert = result.returnData.isEmpty
                    ? "(no revert data)"
                    : Hex.toString(result.returnData)
                status = "relayed but the inner call REVERTED ✗\n\(txHash)\n\(revert)"
            }
        } catch {
            status = "failed — \(error)"
        }
    }
}
