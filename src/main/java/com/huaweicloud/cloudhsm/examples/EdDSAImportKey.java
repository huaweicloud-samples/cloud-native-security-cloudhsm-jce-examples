// 转译自源示例（版权见记录文件）；JCE 算法流程保留，provider 适配 DEW。
package com.huaweicloud.cloudhsm.examples;

import com.huaweicloud.cloudhsm.jce.provider.HsmProvider;
import com.huaweicloud.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.huaweicloud.cloudhsm.jce.provider.attributes.KeyAttributesMap;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Generate an EdDSA Key Pair using BouncyCastle then import it into the HSM
 * This example shows importing EdDSA keys in two methods:
 * 1. through encoded key specs
 * 2. Using the Key Attributes
 */
public class EdDSAImportKey {
    private static String helpString = "EdDSAImportKey\n" +
            "Generate an Ed25519 Key Pair using BouncyCastle then import it into the HSM\n";

    public static void main(String[] args) throws Exception {
        try {
            Security.addProvider(new HsmProvider());
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        // First, generate a keypair with BouncyCastle to test import
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator bcGenerator =
                KeyPairGenerator.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
        KeyPair bcKeyPair = bcGenerator.generateKeyPair();
        System.out.println("Generated Ed25519 key pair with BouncyCastle");

        PrivateKey bcPrivateKey = bcKeyPair.getPrivate();
        PublicKey bcPublicKey = bcKeyPair.getPublic();

        // Method 1: Import the private key using PKCS8EncodedKeySpec and the public key with X509EncodedKeySpec
        // Keys will be generated with default attributes
        // Reference: https://support.huaweicloud.com/api-cloudhsm/
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bcPublicKey.getEncoded());
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bcPrivateKey.getEncoded());
        KeyFactory keyFactory =
                KeyFactory.getInstance("Ed25519", HsmProvider.PROVIDER_NAME);

        
        PublicKey hsmPublicKey = keyFactory.generatePublic(publicKeySpec);
        System.out.println("Imported Ed25519 public key into CloudHSM via X509EncodedKeySpec");
        PrivateKey hsmPrivateKey = keyFactory.generatePrivate(privateKeySpec);
        System.out.println("Imported Ed25519 private key into CloudHSM via PKCS8EncodedKeySpec");

        // Method 2: Import the Key Pair using KeyAttributesMap in order to specify custom key
        // attributes such as setting TOKEN to false.
        
        // Set attributes for Ed25519 public key
        KeyAttributesMap publicKeyAttrsMap = new KeyAttributesMap();
        publicKeyAttrsMap.put(KeyAttribute.LABEL, "ImportedPublicKey");
        publicKeyAttrsMap.put(KeyAttribute.EC_POINT, bcPublicKey.getEncoded());
        publicKeyAttrsMap.put(KeyAttribute.TOKEN, false);
        PublicKey hsmPublicKeyWithAttributes = (PublicKey) keyFactory.generatePublic(publicKeyAttrsMap);
        // Set attributes for Ed25519 private key
        KeyAttributesMap privateKeyAttrsMap = new KeyAttributesMap();
        privateKeyAttrsMap.put(KeyAttribute.LABEL, "ImportedPrivateKey");
        privateKeyAttrsMap.put(KeyAttribute.VALUE, bcPrivateKey.getEncoded());
        privateKeyAttrsMap.put(KeyAttribute.TOKEN, false);
        PrivateKey hsmPrivateKeyWithAttributes = (PrivateKey) keyFactory.generatePrivate(privateKeyAttrsMap);

        KeyPair hsmKeyPairWithAttributes = new KeyPair(hsmPublicKeyWithAttributes, hsmPrivateKeyWithAttributes);
        System.out.println("Imported Ed25519 KeyPair using KeyAttributes");

        // Verify the imported keys work by signing and verifying, cross provider
        String plainText = "This is a test message for imported Ed25519 keys!";
        String signingAlgorithm = "Ed25519";
        byte[] signature = EdDSAOperationsRunner.sign(plainText.getBytes("UTF-8"), hsmPrivateKeyWithAttributes, signingAlgorithm);
        System.out.println("Plaintext signature = " + Base64.getEncoder().encodeToString(signature));

        Signature bcVerifier = Signature.getInstance(signingAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
        bcVerifier.initVerify(bcPublicKey);
        bcVerifier.update(plainText.getBytes("UTF-8"));
        if (bcVerifier.verify(signature)){
            System.out.println("Signature verified");
        } else {
            System.out.println("Signature is invalid!");
        }
    }

    private static void help() {
        System.out.println(helpString);
    }
}
