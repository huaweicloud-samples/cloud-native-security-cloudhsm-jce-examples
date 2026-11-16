// 转译自源示例（版权见记录文件）；JCE 算法流程保留，provider 适配 DEW。
package com.huaweicloud.cloudhsm.examples;

import com.huaweicloud.cloudhsm.jce.provider.HsmProvider;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

/**
 * This sample demonstrates how to encrypt data with AES CTR.
 */
public class AESCTREncryptDecryptRunner {

    public static void main(String[] z) throws Exception {
        try {
            if (Security.getProvider(HsmProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new HsmProvider());
            }
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        // Generate a new AES Key to use for encryption.
        Key key = SymmetricKeys.generateAESKey(256, "AesCtrTest");

        // Generate some random data to encrypt
        byte[] plainText = new byte[1024];
        Random r = new Random();
        r.nextBytes(plainText);

        // Generate Nonce to use with CTR
        byte[] nonce = new byte[8];
        r.nextBytes(nonce);
        // Set nonce portion of the IV
        byte[] ivBytes = new byte[16];
        System.arraycopy(nonce, 0, ivBytes, 0, nonce.length);
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

        byte[] cipherText = encrypt(key, plainText, ivSpec);

        // Decrypt the ciphertext.
        byte[] decryptedText = decrypt(key, cipherText, ivSpec);
        assert(java.util.Arrays.equals(plainText, decryptedText));
        System.out.println("Successful decryption");
    }

    /**
     * Encrypt some plaintext using the CTR cipher mode.
     * @param key
     * @param plainText
     * @param ivSpec
     * @return byte[] containing the cipherText
     */
    public static byte[] encrypt(Key key, byte[] plainText, IvParameterSpec ivSpec) {
        try {
            // Create an encryption cipher.
            Cipher encCipher = Cipher.getInstance("AES/CTR/NoPadding", HsmProvider.PROVIDER_NAME);
            encCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            return encCipher.doFinal(plainText);

        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Decrypt the ciphertext using the CTR cipher mode.
     * @param key
     * @param cipherText
     * @param ivSpec
     * @return byte[] of the decrypted ciphertext.
     */
    public static byte[] decrypt(Key key, byte[] cipherText, IvParameterSpec ivSpec) {
        Cipher decCipher;
        try {

            decCipher = Cipher.getInstance("AES/CTR/NoPadding", HsmProvider.PROVIDER_NAME);
            decCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            return decCipher.doFinal(cipherText);

        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }
}
