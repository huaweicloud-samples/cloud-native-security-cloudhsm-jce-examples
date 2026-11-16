// 转译自源示例（版权见记录文件）；JCE 算法流程保留，provider 适配 DEW。
package com.huaweicloud.cloudhsm.examples;

import com.huaweicloud.cloudhsm.jce.provider.HsmProvider;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;

/**
 * Demonstrate EdDSA sign/verify operations.
 */
public class EdDSAOperationsRunner {

    /**
     * Sign a message using the passed signing algorithm.
     * Supported signature types are documented here: https://support.huaweicloud.com/api-cloudhsm/
     *
     * @param message
     * @param key
     * @param signingAlgorithm
     * @return
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static byte[] sign(byte[] message, PrivateKey key, String signingAlgorithm)
            throws SignatureException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        Signature sig = Signature.getInstance(signingAlgorithm, HsmProvider.PROVIDER_NAME);
        sig.initSign(key);
        sig.update(message);
        return sig.sign();
    }

    /**
     * Verify the signature of a message.
     * Supported signature types are documented here: https://support.huaweicloud.com/api-cloudhsm/
     *
     * @param message
     * @param signature
     * @param publicKey
     * @param signingAlgorithm
     * @return
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static boolean verify(byte[] message, byte[] signature, PublicKey publicKey, String signingAlgorithm)
            throws SignatureException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        Signature sig = Signature.getInstance(signingAlgorithm, HsmProvider.PROVIDER_NAME);
        sig.initVerify(publicKey);
        sig.update(message);
        return sig.verify(signature);
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

        String plainText = "This is a sample Plain Text Message!";

        // Generate an Ed25519 key pair.
        KeyPair kp = AsymmetricKeys.generateEd25519KeyPair("eddsa test");
        
        // Pure EdDSA sign and verify
        System.out.println("Performing Pure EdDSA (Ed25519) sign/verify");
        String signingAlgorithm = "Ed25519";
        byte[] signature = sign(plainText.getBytes("UTF-8"), kp.getPrivate(), signingAlgorithm);
        System.out.println("Plaintext signature = " + Base64.getEncoder().encodeToString(signature));

        if (verify(plainText.getBytes("UTF-8"), signature, kp.getPublic(), signingAlgorithm)) {
            System.out.println("Signature verified");
        } else {
            System.out.println("Signature is invalid!");
        }

        // Hashed EdDSA sign and verify
        System.out.println("Performing Hashed EdDSA (Ed25519ph) sign/verify");
        signingAlgorithm = "Ed25519ph";
        signature = sign(plainText.getBytes("UTF-8"), kp.getPrivate(), signingAlgorithm);
        System.out.println("Plaintext signature = " + Base64.getEncoder().encodeToString(signature));

        if (verify(plainText.getBytes("UTF-8"), signature, kp.getPublic(), signingAlgorithm)) {
            System.out.println("Signature verified");
        } else {
            System.out.println("Signature is invalid!");
        }
    }
}
