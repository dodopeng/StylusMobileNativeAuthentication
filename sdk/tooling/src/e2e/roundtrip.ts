// End-to-end round trip: the FULL mobile pipeline, minus the hardware key.
//
//   1. Generate a P-256 owner (ReferenceSigner == what StrongBox/Secure Enclave
//      produce: a public key (x,y) + raw low-S signatures over a 32-byte digest).
//   2. Deploy a fresh P256Account with that owner, OR attach to ACCOUNT_ADDRESS.
//   3. Read nonce(), build the EIP-712 execute digest, sign it.
//   4. POST {account, data, nonce} to the relayer (the same HttpRelay wire
//      format the SDKs use) — the relayer pays gas and broadcasts.
//   5. Assert nonce() bumped 0 → 1, proving the signature verified on-chain via
//      the RIP-7212 precompile.
//
// This is the missing "sign → relay → on-chain" round trip for the SDK path.
// Hardware can't run headless, but on-chain verification is identical regardless
// of where the key lives, so this exercises every other link for real.
//
// Run (needs a Nitro devnode + the relayer running — see README):
//   RPC_URL=http://localhost:8547 RELAYER_URL=http://localhost:8080 \
//   DEPLOYER_KEY=0x... npm run e2e
import { execFileSync } from 'node:child_process'
import { createPublicClient, http, getAddress, type Address, type Hex } from 'viem'
import { ReferenceSigner } from '../reference/signer.ts'
import { executeDigest, ACCOUNT_ABI, encodeExecute } from '../reference/eip712.ts'

const RPC_URL = process.env.RPC_URL ?? 'http://localhost:8547'
const RELAYER_URL = process.env.RELAYER_URL ?? 'http://localhost:8080'
const WASM = process.env.WASM_PATH ??
  '../../contracts/stylus/target/wasm32-unknown-unknown/release/p256_account.wasm'

const log = (s: string) => console.log(s)

async function main() {
  const pub = createPublicClient({ transport: http(RPC_URL) })
  const chainId = BigInt(await pub.getChainId())
  log(`chain ${chainId} via ${RPC_URL}`)

  const signer = ReferenceSigner.random()
  const owner = signer.publicKey()
  log(`owner x=0x${owner.x.toString(16)} y=0x${owner.y.toString(16)}`)

  const account = await resolveAccount(owner)
  log(`account ${account}`)

  const startNonce = await readNonce(pub, account)
  log(`nonce before: ${startNonce}`)

  // A harmless call: 0 wei, empty data, to a plain EOA by default (which always
  // succeeds). Override TO to exercise other targets. NOTE: targeting the
  // account itself trips Stylus reentrancy and the inner call reverts — the
  // contract still consumes the nonce and reports Executed.success=false.
  const to = (process.env.TO as Address) ?? '0x1111111111111111111111111111111111111111'
  const value = 0n
  const data: Hex = '0x'
  const digest = executeDigest({ chainId, account, to, value, data, nonce: startNonce })
  const signature = signer.sign(digest)
  if (!signer.verify(digest, signature)) throw new Error('local verify failed — would revert on-chain')

  const callData = encodeExecute(to, value, data, startNonce, signature)
  const txHash = await relay(account, callData, startNonce)
  log(`relayed: ${txHash}`)
  await pub.waitForTransactionReceipt({ hash: txHash as Hex })

  const endNonce = await readNonce(pub, account)
  log(`nonce after:  ${endNonce}`)
  if (endNonce !== startNonce + 1n) {
    throw new Error(`FAIL: nonce did not bump (${startNonce} → ${endNonce})`)
  }
  log('✓ PASS: sign → relay → on-chain verify round trip; nonce bumped')
}

/** Use ACCOUNT_ADDRESS if provided, else deploy a fresh account via cargo-stylus. */
async function resolveAccount(owner: { x: bigint; y: bigint }): Promise<Address> {
  if (process.env.ACCOUNT_ADDRESS) return getAddress(process.env.ACCOUNT_ADDRESS)
  const key = process.env.DEPLOYER_KEY
  if (!key) throw new Error('set ACCOUNT_ADDRESS (existing account) or DEPLOYER_KEY (to deploy a fresh one)')

  log('deploying fresh account via cargo stylus…')
  const out = execFileSync(
    'cargo',
    [
      'stylus', 'deploy', '--no-verify',
      '--wasm-file', WASM,
      '--endpoint', RPC_URL,
      '--private-key', key,
      '--constructor-signature', 'constructor(uint256,uint256)',
      '--constructor-args', owner.x.toString(), owner.y.toString(),
    ],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] },
  )
  const m = out.match(/0x[0-9a-fA-F]{40}/)
  if (!m) throw new Error('could not parse deployed address from cargo stylus output')
  return getAddress(m[0])
}

async function readNonce(pub: ReturnType<typeof createPublicClient>, account: Address): Promise<bigint> {
  return (await pub.readContract({ address: account, abi: ACCOUNT_ABI, functionName: 'nonce' })) as bigint
}

async function relay(account: Address, data: Hex, nonce: bigint): Promise<string> {
  const res = await fetch(`${RELAYER_URL}/relay`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ account, data, nonce: Number(nonce) }),
  })
  const json = (await res.json()) as { txHash?: string; error?: string }
  if (!res.ok || !json.txHash) throw new Error(`relay failed (${res.status}): ${json.error ?? 'no txHash'}`)
  return json.txHash
}

main().catch((e) => {
  console.error(String(e?.message ?? e))
  process.exit(1)
})
