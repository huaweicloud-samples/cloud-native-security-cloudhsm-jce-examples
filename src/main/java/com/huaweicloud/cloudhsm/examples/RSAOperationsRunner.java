// 转译自源示例（版权见记录文件）；JCE 算法流程保留，provider 适配 DEW。
package com.huaweicloud.cloudhsm.examples;

import com.huaweicloud.cloudhsm.jce.provider.HsmProvider;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Demonstrate basic RSA operations.
 */
public class RSAOperationsRunner {
    /**
     * Encrypt plainText using the passed transformation.
     * Supported transformations are documented here: https://support.huaweicloud.com/api-cloudhsm/
     *
     * @param transformation
     * @param key
     * @param plainText
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static byte[] encrypt(String transformation, Key key, byte[] plainText)
            throws InvalidKeyException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            NoSuchPaddingException,
            IllegalBlockSizeException,
            BadPaddingException {
        Cipher encCipher = Cipher.getInstance(transformation, HsmProvider.PROVIDER_NAME);
        encCipher.init(Cipher.ENCRYPT_MODE, key);
        return encCipher.doFinal(plainText);
    }

    /**
     * Decrypt cipherText using the passed transformation.
     * Supported transformations are documented here: https://support.huaweicloud.com/api-cloudhsm/
     *
     * @param transformation
     * @param key
     * @param cipherText
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static byte[] decrypt(String transformation, Key key, byte[] cipherText)
            throws InvalidKeyException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            NoSuchPaddingException,
            IllegalBlockSizeException,
            BadPaddingException {
        Cipher decCipher = Cipher.getInstance(transformation, HsmProvider.PROVIDER_NAME);
        decCipher.init(Cipher.DECRYPT_MODE, key);
        return decCipher.doFinal(cipherText);
    }

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
        Signature sig = Signature.getInstance(signingAlgorithm, "CloudHSM");
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
        Signature sig = Signature.getInstance(signingAlgorithm, "CloudHSM");
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
        String transformation = "RSA/ECB/OAEPPadding";

        KeyPair kp = AsymmetricKeys.generateRSAKeyPair(2048, "rsa test");

        System.out.println("Performing RSA Encryption Operation");
        byte[] cipherText = null;
        cipherText = encrypt(transformation, kp.getPublic(), plainText.getBytes(
            StandardCharsets.UTF_8));

        System.out.println("Encrypted plaintext = " + Base64.getEncoder().encodeToString(cipherText));

        byte[] decryptedText = decrypt(transformation, kp.getPrivate(), cipherText);
        System.out.println("Decrypted text = " + new String(decryptedText, StandardCharsets.UTF_8));

        // RSA sign and verify.
        {
            String signingAlgorithm = "SHA512withRSA";
            byte[] signature = sign(plainText.getBytes(StandardCharsets.UTF_8), kp.getPrivate(), signingAlgorithm);
            System.out.println("RSA signature = " + Base64.getEncoder().encodeToString(signature));

            if (verify(plainText.getBytes(StandardCharsets.UTF_8), signature, kp.getPublic(), signingAlgorithm)) {
                System.out.println("Signature verified");
            } else {
                System.out.println("Signature is invalid!");
            }
        }

        // RSA PSS sign and verify.
        {
            String signingAlgorithm = "SHA512withRSA/PSS";
            byte[] signature = sign(plainText.getBytes(StandardCharsets.UTF_8), kp.getPrivate(), signingAlgorithm);
            System.out.println("RSA PSS signature = " + Base64.getEncoder().encodeToString(signature));

            if (verify(plainText.getBytes(StandardCharsets.UTF_8), signature, kp.getPublic(), signingAlgorithm)) {
                System.out.println("Signature verified");
            } else {
                System.out.println("Signature is invalid!");
            }
        }
    }
}
