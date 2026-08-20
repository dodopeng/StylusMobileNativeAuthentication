package xyz.heavenlydev.p256account;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.math.BigInteger;
import java.util.Arrays;

import xyz.heavenlydev.p256account.abi.Abi;
import xyz.heavenlydev.p256account.abi.AbiValue;
import xyz.heavenlydev.p256account.account.Call;
import xyz.heavenlydev.p256account.action.AaveV3;
import xyz.heavenlydev.p256account.action.Erc20;
import xyz.heavenlydev.p256account.action.Erc721;
import xyz.heavenlydev.p256account.action.Native;
import xyz.heavenlydev.p256account.action.UniswapV2;
import xyz.heavenlydev.p256account.crypto.Keccak256;
import xyz.heavenlydev.p256account.crypto.Numeric;
import xyz.heavenlydev.p256account.crypto.P256;
import xyz.heavenlydev.p256account.eip712.Eip712;

/**
 * The Milestone 2 deliverable says the SDK is "Kotlin/Java compatible". This
 * test is written in Java on purpose: it is the only thing that actually proves
 * it. Without {@code @JvmStatic}/{@code @JvmField} every call below would have
 * to go through {@code Erc20.INSTANCE.transfer(...)}, and without
 * {@code @JvmOverloads} the defaulted parameters would all have to be passed
 * explicitly — so this file failing to COMPILE is the real assertion.
 */
public class JavaInteropTest {

    private static final String TOKEN = "0x3333333333333333333333333333333333333333";
    private static final String BOB = "0x2222222222222222222222222222222222222222";
    private static final String ROUTER = "0x5555555555555555555555555555555555555555";
    private static final String POOL = "0x6666666666666666666666666666666666666666";
    private static final String NFT = "0x7777777777777777777777777777777777777777";
    private static final BigInteger AMOUNT = BigInteger.valueOf(1_000_000L);

    @Test
    public void actionTemplatesAreCallableAsStaticsFromJava() {
        // Static call syntax — not Erc20.INSTANCE.transfer(...).
        Call transfer = Erc20.transfer(TOKEN, BOB, AMOUNT);
        assertEquals(TOKEN, transfer.getTo());
        assertEquals("0xa9059cbb", Numeric.bytesToHex(Arrays.copyOfRange(transfer.getData(), 0, 4), true));

        Call approve = Erc20.approve(TOKEN, ROUTER, AMOUNT);
        assertEquals("0x095ea7b3", Numeric.bytesToHex(Arrays.copyOfRange(approve.getData(), 0, 4), true));

        Call nft = Erc721.setApprovalForAll(NFT, BOB, true);
        assertEquals("0xa22cb465", Numeric.bytesToHex(Arrays.copyOfRange(nft.getData(), 0, 4), true));

        Call eth = Native.transfer(BOB, BigInteger.TEN);
        assertEquals(BigInteger.TEN, eth.getValue());
        assertEquals(0, eth.getData().length);
    }

    @Test
    public void defaultedParametersAreReachableFromJavaViaJvmOverloads() {
        // referralCode defaults to 0 in Kotlin; @JvmOverloads generates the
        // shorter Java signature. Without it this line would not compile.
        Call supply = AaveV3.supply(POOL, TOKEN, AMOUNT, BOB);
        assertEquals(POOL, supply.getTo());
        assertEquals("0x617ba037", Numeric.bytesToHex(Arrays.copyOfRange(supply.getData(), 0, 4), true));

        Call borrow = AaveV3.borrow(POOL, TOKEN, AMOUNT, AaveV3.INTEREST_RATE_MODE_VARIABLE, BOB);
        assertEquals("0xa415bcad", Numeric.bytesToHex(Arrays.copyOfRange(borrow.getData(), 0, 4), true));

        // @JvmField constants, accessed as plain static fields.
        assertEquals(BigInteger.valueOf(2), AaveV3.INTEREST_RATE_MODE_VARIABLE);
        assertTrue(P256.HALF_N.compareTo(BigInteger.ZERO) > 0);
        assertTrue(P256.N.compareTo(P256.HALF_N) > 0);
    }

    @Test
    public void coreUtilitiesAreCallableAsStaticsFromJava() {
        assertEquals(
                "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                Numeric.bytesToHex(Keccak256.digest(new byte[0]), true));

        assertEquals("0xd2c88a7c",
                Numeric.bytesToHex(Abi.selector("execute(address,uint256,bytes,uint256,bytes)"), true));

        byte[] encoded = Abi.encodeWithSelector(
                "transfer(address,uint256)",
                Arrays.asList(new AbiValue.Address(BOB), new AbiValue.Uint(AMOUNT)));
        assertEquals(4 + 64, encoded.length);

        byte[] digest = Eip712.executeDigest(
                42161L, "0x1111111111111111111111111111111111111111", BOB,
                BigInteger.ZERO, new byte[0], BigInteger.ZERO);
        assertEquals(32, digest.length);

        // bytesToHex's `prefix` parameter is defaulted in Kotlin — @JvmOverloads
        // exposes the single-argument form to Java.
        assertTrue(Numeric.bytesToHex(digest).startsWith("0x"));
    }

    @Test
    public void swapTemplateAcceptsJavaCollections() {
        Call swap = UniswapV2.swapExactTokensForTokens(
                ROUTER, AMOUNT, BigInteger.valueOf(990_000L),
                Arrays.asList(TOKEN, BOB), BOB, BigInteger.valueOf(1_893_456_000L));
        assertEquals("0x38ed1739", Numeric.bytesToHex(Arrays.copyOfRange(swap.getData(), 0, 4), true));
    }
}
