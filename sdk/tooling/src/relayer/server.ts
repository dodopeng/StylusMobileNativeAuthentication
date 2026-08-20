// Reference relayer service for the P256Account mobile SDKs.
//
// Implements the `HttpRelay` wire format (SPEC.md §4): the phone signs an action
// with its hardware key and POSTs `{account, data, nonce}` here; the relayer
// pays gas and broadcasts the EVM transaction `{to: account, data, value: 0}`.
// The user never needs ETH on-device — the gasless mobile UX.
//
// Security model: the relayer is a *paymaster*, not an authoriser. Authorisation
// is the P-256 signature embedded in `data`, which the contract verifies.
//
// Because the relayer PAYS, the threat is not forged calls — it is legitimate
// ones. Anyone can deploy their own P256Account and sign perfectly valid
// `execute` calls; a selector filter cannot tell those apart from a real user's.
// So the boundary is an **account allowlist** plus per-account and global spend
// budgets and a rate limit (see guard.ts). Requests are also serialised so
// concurrent broadcasts cannot collide on the relayer EOA's nonce.
//
// Configure with:
//   RELAYER_ALLOWLIST=0xabc…,0xdef…   accounts this relayer sponsors (required)
//   PER_ACCOUNT_BUDGET_WEI, GLOBAL_BUDGET_WEI, PER_ACCOUNT_REQUESTS, WINDOW_MS
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import {
  createPublicClient,
  createWalletClient,
  defineChain,
  http,
  isHex,
  type Address,
  type Hex,
} from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { validateRelayRequest, SpendController, DEFAULT_POLICY } from './guard.ts'

const RPC_URL = process.env.RPC_URL ?? 'http://localhost:8547'
const PORT = Number(process.env.PORT ?? 8080)
const MAX_GAS = BigInt(process.env.MAX_GAS ?? '2000000')
const MAX_BODY_BYTES = Number(process.env.MAX_BODY_BYTES ?? 1_000_000)
const PRIVATE_KEY = (process.env.RELAYER_PRIVATE_KEY ?? '') as Hex

const ALLOWLIST = new Set(
  (process.env.RELAYER_ALLOWLIST ?? '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s.length > 0),
)
const POLICY = {
  allowlist: ALLOWLIST,
  perAccountBudgetWei: BigInt(process.env.PER_ACCOUNT_BUDGET_WEI ?? DEFAULT_POLICY.perAccountBudgetWei),
  globalBudgetWei: BigInt(process.env.GLOBAL_BUDGET_WEI ?? DEFAULT_POLICY.globalBudgetWei),
  perAccountRequests: Number(process.env.PER_ACCOUNT_REQUESTS ?? DEFAULT_POLICY.perAccountRequests),
  windowMs: Number(process.env.WINDOW_MS ?? DEFAULT_POLICY.windowMs),
}
const spend = new SpendController(POLICY)

/// Serialises broadcasts. Two concurrent POSTs would otherwise each read the
/// same pending nonce for the relayer EOA and produce colliding transactions,
/// one silently replacing the other.
let broadcastChain: Promise<unknown> = Promise.resolve()
function serialise<T>(fn: () => Promise<T>): Promise<T> {
  const next = broadcastChain.then(fn, fn)
  broadcastChain = next.catch(() => undefined)
  return next
}

if (!isHex(PRIVATE_KEY) || PRIVATE_KEY.length !== 66) {
  console.error('Set RELAYER_PRIVATE_KEY to a 0x-prefixed 32-byte funded EOA key.')
  process.exit(1)
}

const account = privateKeyToAccount(PRIVATE_KEY)

async function main() {
  const probe = createPublicClient({ transport: http(RPC_URL) })
  const chainId = await probe.getChainId()
  const chain = defineChain({
    id: chainId,
    name: `chain-${chainId}`,
    nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
    rpcUrls: { default: { http: [RPC_URL] } },
  })
  const publicClient = createPublicClient({ chain, transport: http(RPC_URL) })
  const wallet = createWalletClient({ account, chain, transport: http(RPC_URL) })

  if (ALLOWLIST.size === 0) {
    console.error(
      'RELAYER_ALLOWLIST is empty — refusing to start.\n' +
      'A relayer pays gas for whatever it broadcasts, so an open endpoint is a\n' +
      'free-gas faucet: anyone can deploy their own P256Account, sign valid\n' +
      'execute calls, and drain it. Set RELAYER_ALLOWLIST=0xacct1,0xacct2,…',
    )
    process.exit(1)
  }
  console.log(
    `relayer ${account.address} on chain ${chainId} via ${RPC_URL}\n` +
    `  gas cap ${MAX_GAS}, sponsoring ${ALLOWLIST.size} account(s)\n` +
    `  budgets: ${POLICY.perAccountBudgetWei} wei/account, ${POLICY.globalBudgetWei} wei global ` +
    `per ${POLICY.windowMs}ms, ${POLICY.perAccountRequests} req/account`,
  )

  const server = createServer((req, res) => {
    handle(req, res, { publicClient, wallet, chainId }).catch((e) => {
      sendJson(res, 500, { error: String(e?.message ?? e) })
    })
  })
  server.listen(PORT, () => console.log(`listening on :${PORT}  (POST /relay, GET /health)`))
}

interface Deps {
  publicClient: ReturnType<typeof createPublicClient>
  wallet: ReturnType<typeof createWalletClient>
  chainId: number
}

async function handle(req: IncomingMessage, res: ServerResponse, deps: Deps) {
  if (req.method === 'GET' && req.url === '/health') {
    const used = spend.spentInWindow()
    sendJson(res, 200, {
      ok: true,
      relayer: account.address,
      chainId: deps.chainId,
      sponsoredAccounts: ALLOWLIST.size,
      windowSpendWei: used.global.toString(),
      globalBudgetWei: POLICY.globalBudgetWei.toString(),
    })
    return
  }
  if (req.method !== 'POST' || req.url !== '/relay') {
    sendJson(res, 404, { error: 'not found' })
    return
  }

  const body = await readBody(req)
  const guard = validateRelayRequest(body.account, body.data)
  if (!guard.ok) return sendJson(res, guard.status, { error: guard.error })
  const acct = body.account as Address
  const data = body.data as Hex

  // Allowlist FIRST, before any RPC work. Checking it last meant an
  // unsponsored address still cost three round-trips (nonce read, gas estimate,
  // gas price) — a free way to load the relayer's RPC quota.
  if (!spend.isSponsored(acct)) {
    return sendJson(res, 403, {
      error:
        'account is not sponsored by this relayer. ' +
        'A relayer pays gas, so it must know whose transactions it funds — ' +
        'set RELAYER_ALLOWLIST.',
    })
  }

  // Fail fast (and avoid wasting gas) if the on-chain nonce already moved past
  // the signed one — the signature would revert with NonceMismatch.
  if (body.nonce !== undefined) {
    const onchain = (await deps.publicClient.readContract({
      address: acct,
      abi: [{ type: 'function', name: 'nonce', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] }],
      functionName: 'nonce',
    })) as bigint
    const signedNonce = BigInt(body.nonce as string | number | bigint)
    if (onchain !== signedNonce) {
      return sendJson(res, 409, { error: `stale nonce: signed ${signedNonce}, on-chain ${onchain}` })
    }
  }

  // Gas estimate + cap, then broadcast.
  let gas: bigint
  try {
    gas = await deps.publicClient.estimateGas({ account: account.address, to: acct, data, value: 0n })
  } catch (e: any) {
    return sendJson(res, 422, { error: `estimateGas reverted: ${e?.shortMessage ?? e?.message}` })
  }
  if (gas > MAX_GAS) return sendJson(res, 413, { error: `gas ${gas} exceeds cap ${MAX_GAS}` })

  // Price the request and check it against the allowlist + budgets BEFORE
  // spending anything.
  const gasWithHeadroom = (gas * 120n) / 100n
  // Fail CLOSED on gas price. Defaulting to 0 made estimatedWei 0, so every
  // budget check trivially passed while the relayer still paid real gas —
  // the budget was disabled exactly when pricing was unavailable.
  let gasPrice: bigint
  try {
    gasPrice = await deps.publicClient.getGasPrice()
  } catch (e: any) {
    return sendJson(res, 503, {
      error: `cannot price this request (getGasPrice failed: ${e?.shortMessage ?? e?.message}); refusing to spend unmetered`,
    })
  }
  if (gasPrice === 0n) {
    return sendJson(res, 503, { error: 'getGasPrice returned 0; refusing to spend unmetered' })
  }
  const estimatedWei = gasWithHeadroom * gasPrice

  const admitted = spend.admit(acct, estimatedWei)
  if (!admitted.ok) return sendJson(res, admitted.status, { error: admitted.error })

  // Serialised: concurrent posts must not race on the relayer EOA's nonce.
  let txHash: Hex
  try {
    txHash = await serialise(() =>
      deps.wallet.sendTransaction({
        account,
        chain: null,
        to: acct,
        data,
        value: 0n,
        gas: gasWithHeadroom,
      }),
    )
  } catch (e) {
    // Nothing was broadcast — give the reservation back.
    spend.release(acct, admitted.reservation)
    throw e
  }

  // Respond immediately — the caller should not wait for a block.
  sendJson(res, 200, { txHash })

  // Reconcile the reservation with what was ACTUALLY spent, once the receipt
  // lands. Settling with `gasWithHeadroom * gasPrice` was a no-op: that is
  // exactly the estimate already reserved, so every reservation permanently
  // booked the 20%-padded figure and the effective budget ran ~20% tighter
  // than configured. Real cost is gasUsed x effectiveGasPrice.
  void deps.publicClient
    .waitForTransactionReceipt({ hash: txHash })
    .then((receipt) => {
      const actual = receipt.gasUsed * (receipt.effectiveGasPrice ?? gasPrice)
      spend.settle(admitted.reservation, actual)
    })
    .catch(() => {
      // Receipt never arrived (dropped/replaced). Keep the padded estimate
      // booked rather than releasing budget for gas that may still be paid —
      // the sliding window will retire it.
    })
}

function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    let raw = ''
    let aborted = false
    req.on('data', (c) => {
      if (aborted) return
      raw += c
      if (raw.length > MAX_BODY_BYTES) {
        // Rejecting the promise is not enough: without destroying the socket
        // the stream keeps delivering data into `raw`, so a single slow POST
        // can exhaust memory. Stop reading, then drop the connection.
        aborted = true
        raw = ''
        reject(new Error('body too large'))
        req.destroy()
      }
    })
    req.on('end', () => {
      if (aborted) return
      try {
        resolve(raw ? JSON.parse(raw) : {})
      } catch {
        reject(new Error('invalid JSON body'))
      }
    })
    req.on('error', reject)
  })
}

function sendJson(res: ServerResponse, status: number, payload: unknown) {
  const text = JSON.stringify(payload)
  res.writeHead(status, { 'content-type': 'application/json' })
  res.end(text)
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
