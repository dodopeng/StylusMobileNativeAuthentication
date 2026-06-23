// Reference relayer service for the P256Account mobile SDKs.
//
// Implements the `HttpRelay` wire format (SPEC.md §4): the phone signs an action
// with its hardware key and POSTs `{account, data, nonce}` here; the relayer
// pays gas and broadcasts the EVM transaction `{to: account, data, value: 0}`.
// The user never needs ETH on-device — the gasless mobile UX.
//
// Security model: the relayer is a *paymaster*, not an authoriser. Authorisation
// is the P-256 signature embedded in `data`, which the contract verifies. The
// relayer additionally refuses to broadcast anything whose selector isn't
// `execute` / `rotateOwner`, and caps gas, so a leaked relayer endpoint can't be
// turned into a generic "send arbitrary calldata" oracle.
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
import { validateRelayRequest } from './guard.ts'

const RPC_URL = process.env.RPC_URL ?? 'http://localhost:8547'
const PORT = Number(process.env.PORT ?? 8080)
const MAX_GAS = BigInt(process.env.MAX_GAS ?? '2000000')
const PRIVATE_KEY = (process.env.RELAYER_PRIVATE_KEY ?? '') as Hex

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

  console.log(`relayer ${account.address} on chain ${chainId} via ${RPC_URL}; gas cap ${MAX_GAS}`)

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
    sendJson(res, 200, { ok: true, relayer: account.address, chainId: deps.chainId })
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

  const txHash = await deps.wallet.sendTransaction({
    account,
    chain: null,
    to: acct,
    data,
    value: 0n,
    gas: (gas * 120n) / 100n, // 20% headroom
  })
  sendJson(res, 200, { txHash })
}

function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    let raw = ''
    req.on('data', (c) => {
      raw += c
      if (raw.length > 1_000_000) reject(new Error('body too large'))
    })
    req.on('end', () => {
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
