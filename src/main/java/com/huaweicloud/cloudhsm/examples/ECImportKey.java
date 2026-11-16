// 转译自源示例（版权见记录文件）；JCE 算法流程保留，provider 适配 DEW。
package com.huaweicloud.cloudhsm.examples;

import com.huaweicloud.cloudhsm.jce.provider.HsmProvider;

import java.io.IOException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import com.huaweicloud.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.huaweicloud.cloudhsm.jce.provider.attributes.KeyAttributesMap;
import com.huaweicloud.cloudhsm.jce.provider.attributes.KeyAttributesMapBuilder;
import com.huaweicloud.cloudhsm.jce.provider.attributes.KeyPairAttributesMap;
import com.huaweicloud.cloudhsm.jce.provider.attributes.KeyPairAttributesMapBuilder;


import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;

/**
 * Generate an EC Key Pair using BouncyCastle then import it into the HSM
 * This function import EC keys in two methods:
 * 1. Through the public/private key specs with default attributes
 * 2. Using Key Attributes explicitly
 */
public class ECImportKey {
    private static String helpString = "ECImportKey\n" +
            "Generate an EC Key Pair using BouncyCastle then import it into the HSM\n";

    public static void main(String[] args) throws Exception {
        try {
            Security.addProvider(new HsmProvider());
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        // First, generate a keypair with BouncyCastle to test import
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator generator =
                KeyPairGenerator.getInstance(
                        "EC", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(new ECGenParameterSpec("prime256v1"));
        KeyPair bcEcKeyPair = generator.generateKeyPair();
        System.out.println("Generated Bouncy Castle EC Key Pair");

        ECPrivateKey bcEcPrivateKey = (ECPrivateKey) bcEcKeyPair.getPrivate();
        ECPublicKey bcEcPublicKey = (ECPublicKey) bcEcKeyPair.getPublic();

        // Method 1: Import the EC Key Pair using the ECPrivateKeySpec and ECPublicKeySpec
        // Keys will be generated with default attributes
        // Reference: https://support.huaweicloud.com/api-cloudhsm/
        ECPrivateKeySpec ecPrivateKeySpec =
                new ECPrivateKeySpec(bcEcPrivateKey.getS(), bcEcPrivateKey.getParams());

        ECPublicKeySpec ecPublicKeySpec =
                new ECPublicKeySpec(bcEcPublicKey.getW(), bcEcPublicKey.getParams());

        KeyFactory keyFactory =
                KeyFactory.getInstance(
                    "EC",
                    HsmProvider.PROVIDER_NAME);

        ECPrivateKey hsmECPrivateKey = (ECPrivateKey) keyFactory.generatePrivate(ecPrivateKeySpec);
        ECPublicKey hsmECPublicKey = (ECPublicKey) keyFactory.generatePublic(ecPublicKeySpec);
        KeyPair hsmKeyPair = new KeyPair(hsmECPublicKey, hsmECPrivateKey);

        System.out.println("Imported EC KeyPair using the ECPrivateKeySpec and ECPublicKeySpec");

        // Method 2: Import the EC Key Pair using KeyAttributesMap in order to specify custom key
        // attributes such as setting TOKEN to false.
        
        // Set attributes for EC public key
        KeyAttributesMap publicKeyAttrsMap = new KeyAttributesMap();
        publicKeyAttrsMap.put(KeyAttribute.LABEL, "ImportedECPublicKey");
        publicKeyAttrsMap.put(KeyAttribute.EC_PARAMS, bcEcPublicKey.getParams());
        publicKeyAttrsMap.put(KeyAttribute.EC_POINT, bcEcPublicKey.getW());
        publicKeyAttrsMap.put(KeyAttribute.TOKEN, false);
        ECPublicKey hsmECPublicKeyWithAttributes = (ECPublicKey) keyFactory.generatePublic(publicKeyAttrsMap);

        // Set attributes for EC private key
        KeyAttributesMap privateKeyAttrsMap = new KeyAttributesMap();
        privateKeyAttrsMap.put(KeyAttribute.LABEL, "ImportedECPrivateKey");
        privateKeyAttrsMap.put(KeyAttribute.EC_PARAMS, bcEcPrivateKey.getParams());
        privateKeyAttrsMap.put(KeyAttribute.VALUE, bcEcPrivateKey.getS().toByteArray());
        privateKeyAttrsMap.put(KeyAttribute.TOKEN, false);
        ECPrivateKey hsmECPrivateKeyWithAttributes = (ECPrivateKey) keyFactory.generatePrivate(privateKeyAttrsMap);

        KeyPair hsmKeyPairWithAttributes = new KeyPair(hsmECPublicKeyWithAttributes, hsmECPrivateKeyWithAttributes);
        System.out.println("Imported EC KeyPair using KeyAttributes");
    }

    private static void help() {
        System.out.println(helpString);
    }
}

