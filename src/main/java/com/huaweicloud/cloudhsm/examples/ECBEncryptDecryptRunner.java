// 转译自源示例（版权见记录文件）；JCE 算法流程保留，provider 适配 DEW。
package com.huaweicloud.cloudhsm.examples;

import com.huaweicloud.cloudhsm.jce.provider.HsmProvider;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Base64;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Demonstrate how to encrypt and decrypt data using AES keys with ECB mode.
 */
public class ECBEncryptDecryptRunner {

    public static void main(final String[] args) throws Exception {
        try {
            if (Security.getProvider(HsmProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new HsmProvider());
            }
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        System.out.println("Using AES to test encrypt/decrypt in ECB mode");
        String transformation = "AES/ECB/NoPadding";
        Key key = SymmetricKeys.generateAESKey(256, "AESECB Test");
        encryptDecrypt(transformation, key);
    }

    /**
     * Encrypt and decrypt a string using the transformation/key supplied by the caller.
     *
     * @param transformation
     * @param key
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static void encryptDecrypt(String transformation, Key key)
            throws NoSuchAlgorithmException,
            NoSuchProviderException,
            NoSuchPaddingException,
            InvalidKeyException,
            UnsupportedEncodingException,
            IllegalBlockSizeException,
            BadPaddingException {

        byte[] plainText = new byte[32];
        new Random().nextBytes(plainText);
        System.out.println("Base64 plain text = " + Base64.getEncoder().encodeToString(plainText));

        // Encrypt the string and display the base64 cipher text
        Cipher encryptCipher = Cipher.getInstance(transformation, HsmProvider.PROVIDER_NAME);
        encryptCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = encryptCipher.doFinal(plainText);

        System.out.println("Base64 cipher text = " + Base64.getEncoder().encodeToString(cipherText));

        // Decrypt the cipher text and display the original string
        Cipher decryptCipher = Cipher.getInstance(transformation, HsmProvider.PROVIDER_NAME);
        decryptCipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedText = decryptCipher.doFinal(cipherText);

        System.out.println("Base64 decrypted text = " + Base64.getEncoder().encodeToString(decryptedText));
    }
}
