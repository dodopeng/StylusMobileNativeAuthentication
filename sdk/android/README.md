# P256Account — Android SDK (Milestone 2)

Native Android SDK for the Arbitrum Stylus `P256Account` smart account. Generates
a non-exportable P-256 key inside **StrongBox** (secure element) or the TEE,
gates every signature behind a **biometric** prompt, builds the exact EIP-712
digest the contract verifies, and relays the signed `execute` / `rotateOwner`
call on-chain.

- Pure-Kotlin Keccak-256 and ABI/EIP-712 (no BouncyCastle / web3j dependency).
- The private key never leaves hardware; only the public key `(x, y)` is exported.
- Interop is pinned by golden tests against the contract (`InteropTest.kt`).

## Requirements

- `minSdk 29` (StrongBox + `BiometricPrompt(CryptoObject)`).
- Host activity must be a `FragmentActivity` (for `BiometricPrompt`).

## Quick start

```kotlin
// 1. Create a hardware key (once per account). Register its (x, y) on-chain by
//    deploying the contract: cargo stylus deploy --constructor-args <x> <y>.
val signer = StrongBoxP256Signer(alias = "p256-account-key", requireBiometric = true)
if (!signer.exists()) {
    val pub = try { signer.create(strongBox = true) }
              catch (e: Exception) { signer.create(strongBox = false) } // no secure element
    // pub.x / pub.y -> deploy the account contract with these as constructor args.
}

// 2. Wire up an account handle against an already-deployed account address.
val rpc   = JsonRpcClient("https://arb1.arbitrum.io/rpc")
val relay = HttpRelay("https://your-relayer.example/relay")   // gasless; pays gas for the user

// StrongBoxP256Signer is itself a SignProvider.
val account = P256Account(
    address = "0xYourDeployedAccount",
    rpc = rpc, relay = relay, signer = signer,
)

// 3. Do things — pass the biometric context per call; each triggers a
//    Face/fingerprint prompt, then relays.
val auth = BiometricAuth(activity, biometricPrompt())
val txHash = account.execute(Erc20.transfer(token = USDC, to = recipient, amount = amount), auth)
account.execute(UniswapV2.swapExactTokensForTokens(router, amountIn, minOut, listOf(USDC, WETH), account.address, deadline), auth)
account.rotateOwner(newHardwareKey.publicKey(), auth)

// A tx hash does NOT mean the inner action succeeded — the contract returns
// (success, returnData) without reverting. Confirm the real outcome:
val result = account.awaitExecuted(txHash)
if (!result.success) { /* inner call reverted; result.returnData has the revert bytes */ }
```

```kotlin
private fun biometricPrompt() = BiometricPrompt.PromptInfo.Builder()
    .setTitle("Confirm transaction")
    .setSubtitle("Sign with your fingerprint or face")
    .setNegativeButtonText("Cancel")
    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
    .build()
```

## Layout

```
p256account/src/main/kotlin/xyz/heavenlydev/p256account/
  crypto/    Keccak256, Numeric (hex/uint256), P256 (DER→raw, low-S, on-curve)
  keystore/  StrongBoxP256Signer (Keystore + BiometricPrompt(CryptoObject))
  eip712/    Eip712 digest construction (typehashes pinned to the contract)
  abi/       Abi encoder + keccak-derived selectors
  rpc/       JsonRpcClient, TransactionRelay (HttpRelay / BroadcasterRelay)
  account/   P256Account, SignProvider, Call
  action/    Erc20 · Erc721 · UniswapV2 · AaveV3 templates (Milestone 4)
```

## Build & test

```bash
cd sdk/android
./gradlew :p256account:testDebugUnitTest   # runs InteropTest (golden vectors)
./gradlew :p256account:assembleRelease      # builds the .aar
```

> The example app referenced in the milestone deliverables is a thin
> `FragmentActivity` wrapper around the Quick start above; the SDK surface and
> golden interop tests are the substantive part and live here.
