// 转译自源示例（版权见记录文件）；JCE 算法流程保留，provider 适配 DEW。
package com.huaweicloud.cloudhsm.examples;

import static com.huaweicloud.cloudhsm.examples.HmacUtil.hmacDigest;

import com.huaweicloud.cloudhsm.jce.provider.HsmProvider;
import com.huaweicloud.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.huaweicloud.cloudhsm.jce.provider.attributes.KeyAttributesMap;
import com.huaweicloud.cloudhsm.jce.provider.attributes.KeyAttributesMapBuilder;

import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;

/**
 * This sample demonstrates wrapping a key out of CloudHSM and unwrapping a key into CloudHSM using
 * various RSA algorithm variants.
 */
public class RSAWrappingRunner {

    private static final String SAMPLE_HMAC_ALGORITHM = "HmacSHA1";

    public static void main(String[] args) throws Exception {
        try {
            if (Security.getProvider(HsmProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new HsmProvider());
            }
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        // Generate a Persistent RSA key pair for wrapping keys.
        // Set attributes for RSA public key. Create persistent key.
        final KeyAttributesMap publicKeyAttrsMap = new KeyAttributesMap();
        publicKeyAttrsMap.put(KeyAttribute.TOKEN, true);

        // Set attributes for RSA private key
        final KeyAttributesMap privateKeyAttrsMap =
                new KeyAttributesMapBuilder().put(KeyAttribute.TOKEN, true).build();

        KeyPair wrappingKeyPair =
                AsymmetricKeys.generateRSAKeyPair(
                        2048, "RsaWrapSample", publicKeyAttrsMap, privateKeyAttrsMap);

        // Generate a new payload key to wrap and unwrap. This sample uses a
        // HMAC key.
        final SecretKey payloadKey =
                (SecretKey) SymmetricKeys.generateHmacKey("RsaWrapPayloadSample");

        // Run the samples.
        rsaOaepWrap(wrappingKeyPair, payloadKey);
        rsaAesWrap(wrappingKeyPair, payloadKey);

        // Remove sample keys from CloudHSM.
        ((Destroyable) wrappingKeyPair.getPublic()).destroy();
        ((Destroyable) wrappingKeyPair.getPrivate()).destroy();
        ((Destroyable) payloadKey).destroy();
    }

    /**
     * This method demonstrates "RSA/ECB/OAEPWithSHA-256ANDMGF1Padding" wrap and unwrap.
     *
     * @param wrappingKeyPair RSA key pair for wrapping
     * @param payloadKey Some payload-key to be wrapped
     */
    private static void rsaOaepWrap(KeyPair wrappingKeyPair, Key payloadKey) throws Exception {
        // Create an RSA OAEP cipher from the CloudHSM provider.
        final Cipher cipher =
                Cipher.getInstance(
                        "RSA/ECB/OAEPWithSHA-256ANDMGF1Padding", HsmProvider.PROVIDER_NAME);

        // Initialize the cipher in wrap mode with the public key.
        cipher.init(Cipher.WRAP_MODE, wrappingKeyPair.getPublic());

        // Wrap the payload key.
        byte[] wrappedKey = cipher.wrap(payloadKey);

        // Initialize an RSA OAEP cipher in unwrap mode using the private key.
        cipher.init(Cipher.UNWRAP_MODE, wrappingKeyPair.getPrivate());

        // Unwrap the key we just wrapped.
        final Key unwrappedKey =
                cipher.unwrap(wrappedKey, SAMPLE_HMAC_ALGORITHM, Cipher.SECRET_KEY);

        // Demonstrate that the unwrapped key matches the original payload key
        // by computing an HMAC digest with each key and comparing the result.
        // Then remove the new unwrapped key from CloudHSM.
        try {
            assert (MessageDigest.isEqual(
                    hmacDigest(payloadKey, SAMPLE_HMAC_ALGORITHM, "RSA OAEP with CloudHSM"),
                    hmacDigest(unwrappedKey, SAMPLE_HMAC_ALGORITHM, "RSA OAEP with CloudHSM")));
            System.out.println(
                    "Verified wrap and unwrap with RSA/ECB/OAEPWithSHA-256ANDMGF1Padding using the"
                            + " CloudHSM provider");
        } finally {
            ((Destroyable) unwrappedKey).destroy();
        }
    }

    /**
     * This method demonstrates "RSAAESWrap" wrap and unwrap.
     *
     * @param wrappingKeyPair RSA key pair for wrapping
     * @param payloadKey Some payload-key to be wrapped
     */
    private static void rsaAesWrap(KeyPair wrappingKeyPair, Key payloadKey) throws Exception {
        // Create an RSA AES cipher from the CloudHSM provider.
        final Cipher cipher =
                Cipher.getInstance(
                        "RSAAESWrap/ECB/OAEPWithSHA-1ANDMGF1Padding",
                        HsmProvider.PROVIDER_NAME);

        // Initialize the cipher in wrap mode with the public key.
        cipher.init(Cipher.WRAP_MODE, wrappingKeyPair.getPublic());

        // Wrap the payload key.
        byte[] wrappedKey = cipher.wrap(payloadKey);

        // Initialize an RSA AES cipher in unwrap mode using the private key.
        cipher.init(Cipher.UNWRAP_MODE, wrappingKeyPair.getPrivate());

        // Unwrap the key we just wrapped.
        final Key unwrappedKey =
                cipher.unwrap(wrappedKey, SAMPLE_HMAC_ALGORITHM, Cipher.SECRET_KEY);

        // Demonstrate that the unwrapped key matches the original payload key
        // by computing an HMAC digest with each key and comparing the result.
        // Then remove the new unwrapped key from CloudHSM.
        try {
            assert (MessageDigest.isEqual(
                    hmacDigest(payloadKey, SAMPLE_HMAC_ALGORITHM, "RSA AES with CloudHSM"),
                    hmacDigest(unwrappedKey, SAMPLE_HMAC_ALGORITHM, "RSA AES with CloudHSM")));
            System.out.println(
                    "Verified wrap and unwrap with RSAAESWrap/ECB/OAEPWithSHA-1ANDMGF1Padding using"
                            + " the CloudHSM provider");
        } finally {
            ((Destroyable) unwrappedKey).destroy();
        }
    }
}
