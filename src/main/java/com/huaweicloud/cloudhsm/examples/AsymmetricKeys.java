// 转译自源示例（版权见记录文件）；JCE 算法流程保留，provider 适配 DEW。
package com.huaweicloud.cloudhsm.examples;

import com.huaweicloud.cloudhsm.jce.jni.MldsaAlgorithm;
import com.huaweicloud.cloudhsm.jce.jni.exception.AddAttributeException;
import com.huaweicloud.cloudhsm.jce.provider.HsmProvider;
import com.huaweicloud.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.huaweicloud.cloudhsm.jce.provider.attributes.KeyAttributesMap;
import com.huaweicloud.cloudhsm.jce.provider.attributes.KeyAttributesMapBuilder;
import com.huaweicloud.cloudhsm.jce.provider.attributes.KeyPairAttributesMap;
import com.huaweicloud.cloudhsm.jce.provider.attributes.KeyPairAttributesMapBuilder;
import com.huaweicloud.cloudhsm.jce.provider.attributes.KeyType;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/** Asymmetric key generation examples. */
public class AsymmetricKeys {
    /**
     * Generate an EC key pair using the given curve. The label passed will be appended with
     * ":Public" and ":Private" for the respective keys. Supported curves are documented here:
     * https://support.huaweicloud.com/api-cloudhsm/ Curve params
     * list: EcParams.EC_CURVE_PRIME256; EcParams.EC_CURVE_PRIME384; EcParams.EC_CURVE_SECP256;
     *
     * @return a key pair object that represents the keys on the HSM.
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static KeyPair generateECKeyPair(
            byte[] curveParams,
            String label,
            KeyAttributesMap additionalPublicKeyAttributes,
            KeyAttributesMap additionalPrivateKeyAtttibutes)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
                    NoSuchProviderException, AddAttributeException {

        final KeyPairGenerator keyPairGen =
                KeyPairGenerator.getInstance("EC", HsmProvider.PROVIDER_NAME);

        // Set attributes for EC public key
        final KeyAttributesMap publicKeyAttrsMap = new KeyAttributesMap();
        publicKeyAttrsMap.putAll(additionalPublicKeyAttributes);
        publicKeyAttrsMap.put(KeyAttribute.LABEL, label + ":Public");
        publicKeyAttrsMap.put(KeyAttribute.EC_PARAMS, curveParams);

        // Set attributes for EC private key
        final KeyAttributesMap privateKeyAttrsMap = new KeyAttributesMap();
        privateKeyAttrsMap.putAll(additionalPrivateKeyAtttibutes);
        privateKeyAttrsMap.put(KeyAttribute.LABEL, label + ":Private");

        // Create KeyPairAttributesMap and use that to initialize the keyPair generator
        KeyPairAttributesMap keyPairSpec =
                new KeyPairAttributesMapBuilder()
                        .withPublic(publicKeyAttrsMap)
                        .withPrivate(privateKeyAttrsMap)
                        .build();
        keyPairGen.initialize(keyPairSpec);

        return keyPairGen.generateKeyPair();
    }

    public static KeyPair generateECKeyPair(byte[] curveParams, String label)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchProviderException, AddAttributeException {
        return generateECKeyPair(curveParams, label, new KeyAttributesMap(), new KeyAttributesMap());
    }

    /**
     * Generate an RSA key pair.
     *
     * <p>The label passed will be appended with ":Public" and ":Private" for the respective keys.
     *
     * @return a key pair object that represents the keys on the HSM.
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static KeyPair generateRSAKeyPair(int keySizeInBits, String label)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
                    NoSuchProviderException, AddAttributeException {
        return generateRSAKeyPair(
                keySizeInBits, label, new KeyAttributesMap(), new KeyAttributesMap());
    }

    /**
     * Generate an RSA key pair and the given provider.
     *
     * <p>The label passed will be appended with ":Public" and ":Private" for the respective keys.
     *
     * @return a key pair object that represents the keys on the HSM.
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static KeyPair generateRSAKeyPair(int keySizeInBits, String label, String providerName)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchProviderException, AddAttributeException {
        return doGenerateRSAKeyPair(
                keySizeInBits, label, new KeyAttributesMap(), new KeyAttributesMap(), providerName);
    }

    /**
     * Generate an RSA key pair.
     *
     * <p>The label passed will be appended with ":Public" and ":Private" for the respective keys.
     *
     * @return a key pair object that represents the keys on the HSM.
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static KeyPair generateRSAKeyPair(
            int keySizeInBits,
            String label,
            KeyAttributesMap additionalPublicKeyAttributes,
            KeyAttributesMap additionalPrivateKeyAttributes)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
                    NoSuchProviderException, AddAttributeException {
        return doGenerateRSAKeyPair(keySizeInBits,
                label,
                additionalPublicKeyAttributes,
                additionalPrivateKeyAttributes,
                HsmProvider.PROVIDER_NAME);
    }

    private static KeyPair doGenerateRSAKeyPair(int keySizeInBits,
                                                String label,
                                                KeyAttributesMap additionalPublicKeyAttributes,
                                                KeyAttributesMap additionalPrivateKeyAttributes,
                                                String providerName)
                                                throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
                                                NoSuchProviderException, AddAttributeException {

        KeyPairGenerator keyPairGen =
                KeyPairGenerator.getInstance("RSA", providerName);

        // Set attributes for RSA public key
        final KeyAttributesMap publicKeyAttrsMap = new KeyAttributesMap();
        publicKeyAttrsMap.putAll(additionalPublicKeyAttributes);
        publicKeyAttrsMap.put(KeyAttribute.LABEL, label + ":Public");
        publicKeyAttrsMap.put(KeyAttribute.MODULUS_BITS, keySizeInBits);
        publicKeyAttrsMap.put(KeyAttribute.PUBLIC_EXPONENT, new BigInteger("65537").toByteArray());

        // Set attributes for RSA private key
        final KeyAttributesMap privateKeyAttrsMap = new KeyAttributesMap();
        privateKeyAttrsMap.putAll(additionalPrivateKeyAttributes);
        privateKeyAttrsMap.put(KeyAttribute.LABEL, label + ":Private");

        // Create KeyPairAttributesMap and use that to initialize the keyPair generator
        KeyPairAttributesMap keyPairSpec =
                new KeyPairAttributesMapBuilder()
                        .withPublic(publicKeyAttrsMap)
                        .withPrivate(privateKeyAttrsMap)
                        .build();

        keyPairGen.initialize(keyPairSpec);

        return keyPairGen.generateKeyPair();
    }

    /**
     * Generate an ML-DSA key pair on the HSM. The label passed will be appended with ":Public" and
     * ":Private" for the respective keys. Supported algorithms are MlDsa44, MlDsa65, and MlDsa87.
     *
     * @return a key pair object that represents the keys on the HSM.
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static KeyPair generateMldsaKeyPair(MldsaAlgorithm algorithm, String label)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
                    NoSuchProviderException, AddAttributeException {
        return doGenerateMldsaKeyPair(
                algorithm, label, new KeyAttributesMap(), new KeyAttributesMap());
    }

    /**
     * Generate an ML-DSA key pair on the HSM with additional key attributes. The label passed will
     * be appended with ":Public" and ":Private" for the respective keys. Supported algorithms are
     * MlDsa44, MlDsa65, and MlDsa87.
     *
     * @return a key pair object that represents the keys on the HSM.
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static KeyPair generateMldsaKeyPair(
            MldsaAlgorithm algorithm,
            String label,
            KeyAttributesMap additionalPublicKeyAttributes,
            KeyAttributesMap additionalPrivateKeyAttributes)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
                    NoSuchProviderException, AddAttributeException {
        return doGenerateMldsaKeyPair(
                algorithm, label, additionalPublicKeyAttributes, additionalPrivateKeyAttributes);
    }

    private static KeyPair doGenerateMldsaKeyPair(
            MldsaAlgorithm algorithm,
            String label,
            KeyAttributesMap additionalPublicKeyAttributes,
            KeyAttributesMap additionalPrivateKeyAttributes)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
                    NoSuchProviderException, AddAttributeException {

        KeyPairGenerator generator =
                KeyPairGenerator.getInstance("ML-DSA", HsmProvider.PROVIDER_NAME);

        KeyAttributesMap publicMap = new KeyAttributesMap();
        publicMap.putAll(additionalPublicKeyAttributes);
        publicMap.put(KeyAttribute.KEY_TYPE, KeyType.MLDSA);
        publicMap.put(KeyAttribute.MLDSA_ALGORITHM, algorithm);
        publicMap.put(KeyAttribute.LABEL, label + ":Public");
        publicMap.put(KeyAttribute.VERIFY, true);

        KeyAttributesMap privateMap = new KeyAttributesMap();
        privateMap.putAll(additionalPrivateKeyAttributes);
        privateMap.put(KeyAttribute.KEY_TYPE, KeyType.MLDSA);
        privateMap.put(KeyAttribute.MLDSA_ALGORITHM, algorithm);
        privateMap.put(KeyAttribute.LABEL, label + ":Private");
        privateMap.put(KeyAttribute.SIGN, true);

        generator.initialize(new KeyPairAttributesMap(publicMap, privateMap), null);
        return generator.generateKeyPair();
    }

    /**
     * Generate an Ed25519 key pair for EdDSA signing. The label passed will be appended with
     * ":Public" and ":Private" for the respective keys. The "Ed25519" algorithm is pre-initialized,
     * no curve specification is needed.
     *
     * @return a key pair object that represents the keys on the HSM.
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static KeyPair generateEd25519KeyPair(
            String label,
            KeyAttributesMap additionalPublicKeyAttributes,
            KeyAttributesMap additionalPrivateKeyAtttibutes)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
                    NoSuchProviderException, AddAttributeException {

        final KeyPairGenerator keyPairGen =
                KeyPairGenerator.getInstance("Ed25519", HsmProvider.PROVIDER_NAME);

        // Set attributes for EdDSA public key
        final KeyAttributesMap publicKeyAttrsMap = new KeyAttributesMap();
        publicKeyAttrsMap.putAll(additionalPublicKeyAttributes);
        publicKeyAttrsMap.put(KeyAttribute.LABEL, label + ":Public");

        // Set attributes for EdDSA private key
        final KeyAttributesMap privateKeyAttrsMap = new KeyAttributesMap();
        privateKeyAttrsMap.putAll(additionalPrivateKeyAtttibutes);
        privateKeyAttrsMap.put(KeyAttribute.LABEL, label + ":Private");

        // Create KeyPairAttributesMap and use that to initialize the keyPair generator
        KeyPairAttributesMap keyPairSpec =
                new KeyPairAttributesMapBuilder()
                        .withPublic(publicKeyAttrsMap)
                        .withPrivate(privateKeyAttrsMap)
                        .build();
        keyPairGen.initialize(keyPairSpec);

        return keyPairGen.generateKeyPair();
    }

    public static KeyPair generateEd25519KeyPair(String label)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchProviderException, AddAttributeException {
        return generateEd25519KeyPair(label, new KeyAttributesMap(), new KeyAttributesMap());
    }
}
