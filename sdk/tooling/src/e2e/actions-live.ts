// Milestone 4 live-chain harness — runs every action template against a REAL
// deployed P256Account on a real chain, satisfying the M4 KPI "each template
// tested end-to-end on Arbitrum One".
//
// It is the same sequence `actions.e2e.test.ts` runs offline against the
// simulator, but the signature is verified by the actual RIP-7212 precompile
// and the nonce advances in real state. Nothing here is template-specific: the
// catalog is shared with the offline suite, so a template added there is
// automatically covered here.
//
// Because the targets are real protocol addresses, most templates are executed
// in DRY-RUN mode by default: the call is built, signed, and its signature
// verified on-chain via the account's own `isValidSignature` (EIP-1271) — which
// exercises the full P-256 path without spending funds or touching live
// protocols. Pass --broadcast to actually submit; see SAFETY below.
//
//   # dry run against Arbitrum One (default: verifies signatures on-chain only)
//   RPC_URL=https://arb1.arbitrum.io/rpc ACCOUNT=0x… npm run e2e:actions
//
//   # Arbitrum Sepolia, really submitting the safe subset via the relayer
//   RPC_URL=https://sepolia-rollup.arbitrum.io/rpc ACCOUNT=0x… \
//   RELAYER_URL=http://localhost:8080 npm run e2e:actions -- --broadcast
//
// SAFETY: --broadcast only submits templates whose target is set via the
// matching env var (TOKEN, ROUTER, POOL, NFT, WETH). Anything still pointing at
// a fixture placeholder is skipped rather than sent to a nonexistent contract.
import { createPublicClient, http, getAddress, type Address, type Hex } from 'viem'
import { ReferenceSigner } from '../reference/signer.ts'
import { executeDigest, ACCOUNT_ABI, encodeExecute } from '../reference/eip712.ts'
import { Native, Erc20, Erc721, Weth, UniswapV2, AaveV3, InterestRateMode, type Call } from '../reference/actions.ts'
import * as f from '../reference/fixtures.ts'

const RPC_URL = process.env.RPC_URL ?? 'http://localhost:8547'
const RELAYER_URL = process.env.RELAYER_URL ?? 'http://localhost:8080'
const BROADCAST = process.argv.includes('--broadcast')

/** Real protocol addresses, if supplied. Templates without one stay dry-run. */
const REAL: Partial<Record<'token' | 'token2' | 'router' | 'pool' | 'nft' | 'weth' | 'to', Address>> = {
  token: process.env.TOKEN as Address | undefined,
  token2: process.env.TOKEN2 as Address | undefined,
  router: process.env.ROUTER as Address | undefined,
  pool: process.env.POOL as Address | undefined,
  nft: process.env.NFT as Address | undefined,
  weth: process.env.WETH as Address | undefined,
  to: process.env.TO as Address | undefined,
}

const TOKEN = REAL.token ?? f.TOKEN
const TOKEN2 = REAL.token2 ?? f.TOKEN2
const ROUTER = REAL.router ?? f.ROUTER
const POOL = REAL.pool ?? f.POOL
const NFT = REAL.nft ?? f.NFT
const WETH = REAL.weth ?? f.WETH
const TO = REAL.to ?? f.BOB

/** `live` = safe to actually broadcast (its target is a real supplied address). */
const CATALOG: Array<{ id: string; call: Call; live: boolean }> = [
  { id: 'native.transfer', call: Native.transfer(TO, 1n), live: !!REAL.to },

  { id: 'erc20.approve', call: Erc20.approve(TOKEN, ROUTER, f.AMOUNT), live: !!REAL.token && !!REAL.router },
  { id: 'erc20.transfer', call: Erc20.transfer(TOKEN, TO, f.AMOUNT), live: false },
  { id: 'erc20.transferFrom', call: Erc20.transferFrom(TOKEN, f.ALICE, TO, f.AMOUNT), live: false },

  { id: 'erc721.approve', call: Erc721.approve(NFT, TO, f.TOKEN_ID), live: false },
  { id: 'erc721.setApprovalForAll', call: Erc721.setApprovalForAll(NFT, TO, true), live: false },
  { id: 'erc721.safeTransferFrom', call: Erc721.safeTransferFrom(NFT, f.ALICE, TO, f.TOKEN_ID), live: false },

  { id: 'weth.deposit', call: Weth.deposit(WETH, 1n), live: !!REAL.weth },
  { id: 'weth.withdraw', call: Weth.withdraw(WETH, 1n), live: !!REAL.weth },

  { id: 'univ2.swapExactTokensForTokens', call: UniswapV2.swapExactTokensForTokens(
      ROUTER, f.AMOUNT, f.AMOUNT_MIN, [TOKEN, TOKEN2], TO, f.DEADLINE), live: false },
  { id: 'univ2.swapExactETHForTokens', call: UniswapV2.swapExactETHForTokens(
      ROUTER, 1n, 0n, [WETH, TOKEN], TO, f.DEADLINE), live: false },
  { id: 'univ2.swapExactTokensForETH', call: UniswapV2.swapExactTokensForETH(
      ROUTER, f.AMOUNT, f.AMOUNT_MIN, [TOKEN, WETH], TO, f.DEADLINE), live: false },

  { id: 'aave.supply', call: AaveV3.supply(POOL, TOKEN, f.AMOUNT, TO), live: false },
  { id: 'aave.borrow', call: AaveV3.borrow(POOL, TOKEN, f.AMOUNT, InterestRateMode.Variable, TO), live: false },
  { id: 'aave.repay', call: AaveV3.repay(POOL, TOKEN, f.AMOUNT, InterestRateMode.Variable, TO), live: false },
  { id: 'aave.withdraw', call: AaveV3.withdraw(POOL, TOKEN, f.AMOUNT, TO), live: false },
]

const EIP1271_MAGIC = '0x1626ba7e'

async function main() {
  const accountEnv = process.env.ACCOUNT
  if (!accountEnv) throw new Error('set ACCOUNT=<deployed P256Account address>')
  const account = getAddress(accountEnv)

  const pub = createPublicClient({ transport: http(RPC_URL) })
  const chainId = BigInt(await pub.getChainId())
  console.log(`chain ${chainId} via ${RPC_URL}`)
  console.log(`account ${account}`)
  console.log(BROADCAST ? 'mode: BROADCAST (live templates will be submitted)' : 'mode: dry-run (EIP-1271 verification only)')

  // The signer MUST be the account's current owner or every signature fails
  // verification. There is no sensible default here: a random key would produce
  // 16 confusing FAILs that look like template bugs rather than a missing env
  // var, so require it explicitly and check it against on-chain state below.
  if (!process.env.OWNER_KEY) {
    throw new Error(
      'set OWNER_KEY=0x… — the P-256 private key of the account owner.\n' +
      'Without it no signature can verify and every template would report a false failure.',
    )
  }
  const signer = ReferenceSigner.fromPrivateKey(process.env.OWNER_KEY as Hex)

  // Fail fast and unambiguously if the key does not match the deployed owner,
  // rather than reporting it as 16 separate template failures.
  const { x, y } = signer.publicKey()
  const [onChainX, onChainY] = await Promise.all([
    pub.readContract({ address: account, abi: ACCOUNT_ABI, functionName: 'ownerX' }) as Promise<bigint>,
    pub.readContract({ address: account, abi: ACCOUNT_ABI, functionName: 'ownerY' }) as Promise<bigint>,
  ])
  if (x !== onChainX || y !== onChainY) {
    throw new Error(
      `OWNER_KEY does not match the account owner.\n` +
      `  on-chain: x=0x${onChainX.toString(16)} y=0x${onChainY.toString(16)}\n` +
      `  supplied: x=0x${x.toString(16)} y=0x${y.toString(16)}`,
    )
  }
  console.log('owner key matches on-chain owner')

  let passed = 0, skipped = 0, failed = 0

  for (const { id, call, live } of CATALOG) {
    const nonce = await readNonce(pub, account)
    const digest = executeDigest({
      chainId, account, to: call.to, value: call.value, data: call.data, nonce,
    })
    const signature = signer.sign(digest)

    if (!signer.verify(digest, signature)) {
      console.log(`FAIL  ${id}  local P-256 verify failed`)
      failed++
      continue
    }

    // On-chain verification through the account's EIP-1271 path — this is the
    // real RIP-7212 precompile checking a real SDK signature over this exact
    // template's digest. No gas, no state change.
    const magic = await pub.readContract({
      address: account, abi: ACCOUNT_ABI, functionName: 'isValidSignature',
      args: [digest, signature],
    }) as Hex

    if (magic.toLowerCase() !== EIP1271_MAGIC) {
      console.log(`FAIL  ${id}  on-chain isValidSignature returned ${magic}`)
      failed++
      continue
    }

    if (!BROADCAST || !live) {
      console.log(`OK    ${id}  signature verified on-chain${live ? '' : ' (dry-run: no real target configured)'}`)
      if (!live) skipped++
      passed++
      continue
    }

    const callData = encodeExecute(call.to, call.value, call.data, nonce, signature)
    const txHash = await relay(account, callData, nonce)
    const receipt = await pub.waitForTransactionReceipt({ hash: txHash })
    const after = await readNonce(pub, account)

    if (after !== nonce + 1n) {
      console.log(`FAIL  ${id}  nonce did not advance (${nonce} → ${after})`)
      failed++
      continue
    }
    console.log(`OK    ${id}  broadcast ${txHash} (block ${receipt.blockNumber}), nonce ${nonce} → ${after}`)
    passed++
  }

  console.log(`\n${passed}/${CATALOG.length} templates verified, ${skipped} dry-run only, ${failed} failed`)
  if (failed > 0) process.exit(1)
}

async function readNonce(pub: ReturnType<typeof createPublicClient>, account: Address): Promise<bigint> {
  return await pub.readContract({
    address: account, abi: ACCOUNT_ABI, functionName: 'nonce',
  }) as bigint
}

async function relay(account: Address, data: Hex, nonce: bigint): Promise<Hex> {
  const res = await fetch(`${RELAYER_URL}/relay`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ account, data, nonce: nonce.toString() }),
  })
  if (!res.ok) throw new Error(`relayer ${res.status}: ${await res.text()}`)
  const body = await res.json() as { txHash: Hex }
  return body.txHash
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
