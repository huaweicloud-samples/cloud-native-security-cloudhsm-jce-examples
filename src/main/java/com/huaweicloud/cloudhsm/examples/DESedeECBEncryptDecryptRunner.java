// 转译自源示例（版权见记录文件）；JCE 算法流程保留，provider 适配 DEW。
package com.huaweicloud.cloudhsm.examples;

import com.huaweicloud.cloudhsm.jce.provider.HsmProvider;
import java.io.IOException;
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

/**
 * This sample demonstrates how to encrypt data with DESede ECB.
 */
public class DESedeECBEncryptDecryptRunner {

    public static void main(String[] z) throws Exception {
        try {
            if (Security.getProvider(HsmProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new HsmProvider());
            }
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        // Generate a new DES Key to use for encryption.
        Key key = SymmetricKeys.generateDESKey("DesEcbTest");

        // Generate some random data to encrypt
        byte[] plainText = new byte[1024];
        Random r = new Random();
        r.nextBytes(plainText);

        // Encrypt the plaintext
        byte[] cipherText = encrypt(key, plainText);
        // Decrypt the ciphertext.
        byte[] decryptedText = decrypt(key, cipherText);
        assert(java.util.Arrays.equals(plainText, decryptedText));
        System.out.println("Successful decryption");
    }

    /**
     * Encrypt some plaintext using the DESede ECB cipher mode.
     * @param key
     * @param plainText
     * @return byte[] containing encrypted data
     */
    public static byte[] encrypt(Key key, byte[] plainText) {
        try {
            // Create an encryption cipher.
            Cipher encCipher = Cipher.getInstance("DESede/ECB/NoPadding", HsmProvider.PROVIDER_NAME);
            encCipher.init(Cipher.ENCRYPT_MODE, key);
            return encCipher.doFinal(plainText);

        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Decrypt the ciphertext using the DESede ECB cipher mode.
     * @param key
     * @param cipherText
     * @return byte[] of the decrypted ciphertext.
     */
    public static byte[] decrypt(Key key, byte[] cipherText) {
        Cipher decCipher;
        try {
            decCipher = Cipher.getInstance("DESede/ECB/NoPadding", HsmProvider.PROVIDER_NAME);
            decCipher.init(Cipher.DECRYPT_MODE, key);
            return decCipher.doFinal(cipherText);

        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }
}
