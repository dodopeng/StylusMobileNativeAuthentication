package xyz.heavenlydev.p256account.example

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import xyz.heavenlydev.p256account.account.BiometricAuth
import xyz.heavenlydev.p256account.account.Call
import xyz.heavenlydev.p256account.account.P256Account
import xyz.heavenlydev.p256account.example.databinding.ActivityMainBinding
import xyz.heavenlydev.p256account.keystore.StrongBoxP256Signer
import xyz.heavenlydev.p256account.rpc.HttpRelay
import xyz.heavenlydev.p256account.rpc.JsonRpcClient
import java.math.BigInteger

/**
 * Minimal end-to-end demo of the P256Account SDK:
 *   1. create / load a hardware P-256 key (StrongBox or TEE);
 *   2. point at a deployed account + relayer;
 *   3. sign a test `execute` behind a biometric and relay it.
 *
 * The (x, y) shown in step 1 are the constructor args used to deploy the
 * account contract — `cargo stylus deploy --constructor-args <x> <y>`.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val signer by lazy { StrongBoxP256Signer(alias = ALIAS, requireBiometric = true) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnCreateKey.setOnClickListener { createOrLoadKey() }
        binding.btnSend.setOnClickListener { sendTestExecute() }
    }

    private fun createOrLoadKey() {
        try {
            if (!signer.exists()) {
                // Prefer the secure element; fall back to TEE if absent (some
                // StrongBox parts reject the raw-ECDSA key this SDK needs).
                try { signer.create(strongBox = true) } catch (e: Exception) { signer.create(strongBox = false) }
            }
            val pub = signer.publicKey()
            binding.txtPubKey.text = "x = 0x${pub.x.toString(16)}\ny = 0x${pub.y.toString(16)}\n" +
                "→ deploy: cargo stylus deploy --constructor-args ${pub.x} ${pub.y}"
        } catch (e: Exception) {
            binding.txtPubKey.text = "key error: ${e.message}"
        }
    }

    private fun sendTestExecute() {
        val account = binding.inAccount.text.toString().trim()
        if (account.length != 42) {
            binding.txtStatus.text = "status: enter a deployed account address first"
            return
        }
        if (BiometricManager.from(this).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            != BiometricManager.BIOMETRIC_SUCCESS
        ) {
            binding.txtStatus.text = "status: no biometric enrolled on this device"
            return
        }

        val rpc = JsonRpcClient(binding.inRpc.text.toString().trim())
        val relay = HttpRelay(binding.inRelay.text.toString().trim())
        // The signer is itself a SignProvider; the biometric prompt context is
        // threaded in per call via BiometricAuth.
        val p256 = P256Account(address = account, rpc = rpc, relay = relay, signer = signer)
        val auth = BiometricAuth(this, prompt())

        binding.txtStatus.text = "status: signing…"
        lifecycleScope.launch {
            try {
                // A harmless self-call (0 wei, empty data) — exercises the full
                // sign → relay → on-chain path without touching real funds.
                val txHash = p256.execute(Call(to = account, value = BigInteger.ZERO), auth)
                binding.txtStatus.text = "status: relayed ✓\n$txHash"
            } catch (e: Exception) {
                binding.txtStatus.text = "status: failed — ${e.message}"
            }
        }
    }

    private fun prompt() = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Confirm transaction")
        .setSubtitle("Sign with your fingerprint or face")
        .setNegativeButtonText("Cancel")
        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        .build()

    companion object {
        private const val ALIAS = "p256-account-demo-key"
    }
}
