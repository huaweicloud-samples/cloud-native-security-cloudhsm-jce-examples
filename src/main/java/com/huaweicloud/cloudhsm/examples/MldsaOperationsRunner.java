// 转译自源示例（版权见记录文件）；JCE 算法流程保留，provider 适配 DEW。
package com.huaweicloud.cloudhsm.examples;

import com.huaweicloud.cloudhsm.jce.jni.MldsaAlgorithm;
import com.huaweicloud.cloudhsm.jce.provider.HsmProvider;

import java.io.IOException;
import java.security.KeyPair;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;
import java.util.Base64;
import javax.security.auth.Destroyable;

/**
 * Demonstrates ML-DSA key generation, sign/verify (pure), and sign/verify (external MU).
 *
 * <p>Supported algorithms: ML-DSA-44, ML-DSA-65, ML-DSA-87.
 *
 * <p>Usage:
 * <pre>
 *   java MldsaOperationsRunner
 *   java MldsaOperationsRunner --algorithm ML-DSA-65
 * </pre>
 */
public class MldsaOperationsRunner {

    private static final String MLDSA_ALGORITHM = "ML-DSA";
    private static final String MLDSA_EXTERNAL_MU_ALGORITHM = "ML-DSA-EXTERNAL-MU";

    /**
     * Generate an ML-DSA key pair on the HSM.
     */
    public static KeyPair generateMldsaKeyPair(MldsaAlgorithm algorithm, String label)
            throws Exception {
        return AsymmetricKeys.generateMldsaKeyPair(algorithm, label);
    }

    /**
     * Sign a message using ML-DSA (pure mode).
     */
    public static byte[] sign(byte[] message, KeyPair keyPair) throws Exception {
        Signature signer = Signature.getInstance(MLDSA_ALGORITHM, HsmProvider.PROVIDER_NAME);
        signer.initSign(keyPair.getPrivate());
        signer.update(message);
        return signer.sign();
    }

    /**
     * Verify a signature using ML-DSA (pure mode).
     */
    public static boolean verify(byte[] message, byte[] signature, KeyPair keyPair)
            throws Exception {
        Signature verifier =
                Signature.getInstance(MLDSA_ALGORITHM, HsmProvider.PROVIDER_NAME);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(message);
        return verifier.verify(signature);
    }

    /**
     * Sign using ML-DSA with external MU. The data passed in must be a precomputed 64-byte mu
     * value (as defined in FIPS 204), not the raw message.
     */
    public static byte[] signExternalMu(byte[] mu, KeyPair keyPair) throws Exception {
        Signature signer =
                Signature.getInstance(MLDSA_EXTERNAL_MU_ALGORITHM, HsmProvider.PROVIDER_NAME);
        signer.initSign(keyPair.getPrivate());
        signer.update(mu);
        return signer.sign();
    }

    /**
     * Verify using ML-DSA with external MU. The data passed in must be a precomputed 64-byte mu
     * value (as defined in FIPS 204), not the raw message.
     */
    public static boolean verifyExternalMu(byte[] mu, byte[] signature, KeyPair keyPair)
            throws Exception {
        Signature verifier =
                Signature.getInstance(MLDSA_EXTERNAL_MU_ALGORITHM, HsmProvider.PROVIDER_NAME);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(mu);
        return verifier.verify(signature);
    }

    /** Delete the key pair from the HSM. */
    private static void deleteKeyPair(KeyPair keyPair) throws Exception {
        try {
            ((Destroyable) keyPair.getPrivate()).destroy();
        } catch (Exception e) {
            System.err.println("Failed to delete private key: " + e.getMessage());
        }
        try {
            ((Destroyable) keyPair.getPublic()).destroy();
        } catch (Exception e) {
            System.err.println("Failed to delete public key: " + e.getMessage());
        }
    }

    private static MldsaAlgorithm parseMldsaAlgorithm(String name) {
        switch (name) {
            case "ML-DSA-44":
                return MldsaAlgorithm.MlDsa44;
            case "ML-DSA-65":
                return MldsaAlgorithm.MlDsa65;
            case "ML-DSA-87":
                return MldsaAlgorithm.MlDsa87;
            default:
                throw new IllegalArgumentException(
                        "Unsupported: " + name + ". Use ML-DSA-44, ML-DSA-65, or ML-DSA-87.");
        }
    }

    public static void main(final String[] args) throws Exception {
        try {
            if (Security.getProvider(HsmProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new HsmProvider());
            }
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        String algorithmName = "ML-DSA-44";
        for (int i = 0; i < args.length; i++) {
            if ("--algorithm".equals(args[i])) {
                algorithmName = args[++i];
            }
        }

        MldsaAlgorithm algorithm = parseMldsaAlgorithm(algorithmName);
        System.out.println("=== ML-DSA Operations (" + algorithmName + ") ===\n");

        // 1. Key Generation
        System.out.println("1. Generating ML-DSA key pair...");
        KeyPair keyPair = generateMldsaKeyPair(algorithm, "mldsa-example");
        System.out.println("   Key pair generated successfully.\n");

        // 2. Pure ML-DSA Sign and Verify
        System.out.println("2. Pure ML-DSA Sign/Verify...");
        byte[] message = "Hello, post-quantum world!".getBytes("UTF-8");
        byte[] signature = sign(message, keyPair);
        System.out.println("   Signature: " + Base64.getEncoder().encodeToString(signature));

        boolean verified = verify(message, signature, keyPair);
        System.out.println("   Verified: " + verified + "\n");

        // 3. External MU Sign and Verify (requires a precomputed 64-byte mu value)
        System.out.println("3. External MU Sign/Verify...");
        byte[] mu = new byte[64];
        Arrays.fill(mu, (byte) 1);
        byte[] muSignature = signExternalMu(mu, keyPair);
        System.out.println("   Signature: " + Base64.getEncoder().encodeToString(muSignature));

        boolean muVerified = verifyExternalMu(mu, muSignature, keyPair);
        System.out.println("   Verified: " + muVerified + "\n");

        // 4. Cleanup
        System.out.println("4. Deleting key pair...");
        deleteKeyPair(keyPair);
        System.out.println("   Done.");
    }
}
