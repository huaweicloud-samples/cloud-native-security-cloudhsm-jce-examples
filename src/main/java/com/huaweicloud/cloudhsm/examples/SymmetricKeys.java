// 转译自源示例（版权见记录文件）；JCE 算法流程保留，provider 适配 DEW。
package com.huaweicloud.cloudhsm.examples;

import com.huaweicloud.cloudhsm.jce.jni.exception.AddAttributeException;
import com.huaweicloud.cloudhsm.jce.provider.HsmProvider;
import com.huaweicloud.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.huaweicloud.cloudhsm.jce.provider.attributes.KeyAttributesMap;

import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/** Symmetric key generation examples. */
public class SymmetricKeys {
    /**
     * Generate an AES key with a specific label and keysize.
     *
     * @param keySizeInBits Size of the key.
     * @param keyLabel Label to associate with the key.
     */
    public static Key generateAESKey(int keySizeInBits, String keyLabel)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
                    NoSuchProviderException, AddAttributeException {
        return generateAESKey(keySizeInBits, keyLabel, new KeyAttributesMap());
    }

    /**
     * Generate an AES key with a specific label and keysize.
     *
     * @param keySizeInBits Size of the key.
     * @param keyLabel Label to associate with the key.
     */
    public static Key generateAESKey(
            int keySizeInBits, String keyLabel, KeyAttributesMap aesSpecKeyAttributes)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
                    NoSuchProviderException, AddAttributeException {

        // Create an Aes keygen Algorithm parameter spec using KeyAttributesMap
        final KeyAttributesMap aesSpec = new KeyAttributesMap();
        aesSpec.putAll(aesSpecKeyAttributes);
        aesSpec.put(KeyAttribute.LABEL, keyLabel);
        aesSpec.put(KeyAttribute.SIZE, keySizeInBits);

        KeyGenerator keyGen = KeyGenerator.getInstance("AES", HsmProvider.PROVIDER_NAME);
        keyGen.init(aesSpec);
        SecretKey aesKey = keyGen.generateKey();

        return aesKey;
    }

    /**
     * Generate a Hmac key with a specific label.
     *
     * @param keyLabel Label to associate with the key.
     */
    public static Key generateHmacKey(String keyLabel)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
                    NoSuchProviderException, AddAttributeException {

        // Create an Hmac keygen Algorithm parameter spec using KeyAttributesMap
        KeyAttributesMap hmacSpec = new KeyAttributesMap();
        hmacSpec.put(KeyAttribute.LABEL, keyLabel);
        hmacSpec.put(KeyAttribute.SIZE, 192);

        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA1", HsmProvider.PROVIDER_NAME);
        keyGen.init(hmacSpec);
        SecretKey hmacKey = keyGen.generateKey();

        return hmacKey;
    }

    /**
     * Generate a DES key with a specific label.
     *
     * @param keyLabel
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static Key generateDESKey(String keyLabel)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
                    NoSuchProviderException, AddAttributeException {
        return doGenerateDESKey(keyLabel, HsmProvider.PROVIDER_NAME);
    }

    /**
     * Generate a DES key with a specific label and given provider.
     *
     * @param keyLabel
     * @param providerName provider to be used
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static Key doGenerateDESKey(String keyLabel, String providerName)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException,
            AddAttributeException{
        // Create a Des3 keygen Algorithm parameter spec using KeyAttributesMap
        KeyAttributesMap desSpec = new KeyAttributesMap();
        desSpec.put(KeyAttribute.LABEL, keyLabel);

        KeyGenerator keyGen = KeyGenerator.getInstance("DESede", providerName);
        keyGen.init(desSpec);
        SecretKey des3Key = keyGen.generateKey();
        return des3Key;
    }
}
