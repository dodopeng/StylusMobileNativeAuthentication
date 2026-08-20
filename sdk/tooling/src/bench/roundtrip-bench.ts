// Milestone 2 KPI — "biometric signing round-trip time (sign + on-chain
// confirmation) under 30 seconds".
//
// That KPI spans three legs, and only some can be measured without hardware:
//
//   [1] SDK compute      digest → sign → ABI encode        measured here
//   [2] biometric prompt user sees Face ID / fingerprint    needs a device
//   [3] chain leg        relay → broadcast → confirmation   needs a live chain
//
// This harness measures leg [1] exactly, and measures leg [3] too when pointed
// at a chain (RPC_URL + ACCOUNT + OWNER_KEY + RELAYER_URL). It deliberately does
// NOT extrapolate: a number for leg [1] is not a claim about the KPI, it is the
// share of the 30s budget the SDK itself consumes.
//
//   npm run bench                 # leg [1] only, offline
//   RPC_URL=… ACCOUNT=0x… OWNER_KEY=0x… RELAYER_URL=… npm run bench -- --chain
import { createPublicClient, http, getAddress, type Address, type Hex } from 'viem'
import { ReferenceSigner } from '../reference/signer.ts'
import { executeDigest, encodeExecute, ACCOUNT_ABI } from '../reference/eip712.ts'
import { Erc20 } from '../reference/actions.ts'
import * as f from '../reference/fixtures.ts'

const ITERATIONS = Number(process.env.ITERATIONS ?? 1000)
const WITH_CHAIN = process.argv.includes('--chain')
const CHAIN_ID = 42161n
const ACCOUNT_FIXTURE: Address = '0x00000000000000000000000000000000000000aa'

interface Stats { p50: number; p95: number; max: number; mean: number }

function stats(samples: number[]): Stats {
  const s = [...samples].sort((a, b) => a - b)
  const at = (q: number) => s[Math.min(s.length - 1, Math.floor(q * s.length))]
  return {
    p50: at(0.5),
    p95: at(0.95),
    max: s[s.length - 1],
    mean: s.reduce((a, b) => a + b, 0) / s.length,
  }
}

const ms = (n: number) => `${n.toFixed(3)} ms`

function row(label: string, st: Stats) {
  console.log(
    `${label.padEnd(28)} p50 ${ms(st.p50).padStart(10)}   ` +
    `p95 ${ms(st.p95).padStart(10)}   max ${ms(st.max).padStart(10)}`,
  )
}

function benchLocal() {
  const signer = ReferenceSigner.random()
  const call = Erc20.transfer(f.TOKEN, f.BOB, f.AMOUNT)

  const digestT: number[] = []
  const signT: number[] = []
  const encodeT: number[] = []
  const totalT: number[] = []

  for (let i = 0; i < ITERATIONS; i++) {
    const nonce = BigInt(i)
    const t0 = performance.now()

    const digest = executeDigest({
      chainId: CHAIN_ID, account: ACCOUNT_FIXTURE,
      to: call.to, value: call.value, data: call.data, nonce,
    })
    const t1 = performance.now()

    const signature = signer.sign(digest)
    const t2 = performance.now()

    encodeExecute(call.to, call.value, call.data, nonce, signature)
    const t3 = performance.now()

    digestT.push(t1 - t0)
    signT.push(t2 - t1)
    encodeT.push(t3 - t2)
    totalT.push(t3 - t0)
  }

  console.log(`\nLeg [1] — SDK compute, ${ITERATIONS} iterations\n`)
  row('EIP-712 digest', stats(digestT))
  row('P-256 sign (software)', stats(signT))
  row('ABI encode execute', stats(encodeT))
  console.log('-'.repeat(78))
  row('TOTAL SDK compute', stats(totalT))

  const t = stats(totalT)
  console.log(
    `\nSDK compute consumes ${(t.p95 / 30_000 * 100).toFixed(4)}% of the 30s budget at p95 ` +
    `(${ms(t.p95)} of 30000 ms).`,
  )
  console.log(
    'NOTE: the signature here is produced in software by @noble/curves, NOT by a\n' +
    '      Secure Enclave or StrongBox. Hardware signing is slower and is gated on\n' +
    '      a biometric prompt whose duration is set by the user, not the SDK.\n' +
    '      Leg [2] is therefore NOT measured by this number.',
  )
  return t
}

async function benchChain(localP95: number) {
  const { RPC_URL, ACCOUNT, OWNER_KEY, RELAYER_URL } = process.env
  if (!RPC_URL || !ACCOUNT || !OWNER_KEY || !RELAYER_URL) {
    throw new Error('--chain needs RPC_URL, ACCOUNT, OWNER_KEY and RELAYER_URL')
  }
  const account = getAddress(ACCOUNT)
  const pub = createPublicClient({ transport: http(RPC_URL) })
  const chainId = BigInt(await pub.getChainId())
  const signer = ReferenceSigner.fromPrivateKey(OWNER_KEY as Hex)

  const samples = Number(process.env.CHAIN_ITERATIONS ?? 3)
  const relayT: number[] = []
  const confirmT: number[] = []
  const totalT: number[] = []

  console.log(`\nLeg [3] — chain round trip on chain ${chainId}, ${samples} samples\n`)

  for (let i = 0; i < samples; i++) {
    const nonce = await pub.readContract({
      address: account, abi: ACCOUNT_ABI, functionName: 'nonce',
    }) as bigint

    // A harmless no-op call: 0 wei, empty data, to a plain address.
    const to = f.BOB
    const digest = executeDigest({ chainId, account, to, value: 0n, data: '0x', nonce })
    const callData = encodeExecute(to, 0n, '0x', nonce, signer.sign(digest))

    const t0 = performance.now()
    const res = await fetch(`${RELAYER_URL}/relay`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ account, data: callData, nonce: nonce.toString() }),
    })
    if (!res.ok) throw new Error(`relayer ${res.status}: ${await res.text()}`)
    const { txHash } = await res.json() as { txHash: Hex }
    const t1 = performance.now()

    await pub.waitForTransactionReceipt({ hash: txHash })
    const t2 = performance.now()

    relayT.push(t1 - t0)
    confirmT.push(t2 - t1)
    totalT.push(t2 - t0)
    console.log(`  sample ${i + 1}: relay ${ms(t1 - t0)}, confirm ${ms(t2 - t1)}  ${txHash}`)
  }

  console.log()
  row('relay accept', stats(relayT))
  row('block confirmation', stats(confirmT))
  console.log('-'.repeat(78))
  row('TOTAL chain leg', stats(totalT))

  const chain = stats(totalT)
  const measured = localP95 + chain.p95
  console.log(
    `\nMeasured legs [1]+[3] at p95: ${ms(measured)} ` +
    `(${(measured / 30_000 * 100).toFixed(2)}% of the 30s budget).`,
  )
  console.log(
    `Remaining headroom for leg [2] (hardware sign + biometric prompt): ` +
    `${ms(30_000 - measured)}.`,
  )
  console.log(
    measured < 30_000
      ? 'PASS so far — but the KPI is only settled by an on-device measurement.'
      : 'FAIL — measured legs alone already exceed the 30s budget.',
  )
}

const local = benchLocal()
if (WITH_CHAIN) {
  await benchChain(local.p95)
} else {
  console.log('\nRun with --chain (and RPC_URL/ACCOUNT/OWNER_KEY/RELAYER_URL) to measure leg [3].')
}
