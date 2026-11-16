// 转译自源示例（版权见记录文件）；JCE 算法流程保留，provider 适配 DEW。
package com.huaweicloud.cloudhsm.examples;

import com.huaweicloud.cloudhsm.jce.provider.HsmProvider;
import com.huaweicloud.cloudhsm.jce.provider.attributes.EcParams;
import com.huaweicloud.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.huaweicloud.cloudhsm.jce.provider.attributes.KeyAttributesMap;
import com.huaweicloud.cloudhsm.jce.provider.attributes.KeyAttributesMapBuilder;
import com.huaweicloud.cloudhsm.jce.provider.attributes.KeyPairAttributesMap;
import com.huaweicloud.cloudhsm.jce.provider.attributes.KeyPairAttributesMapBuilder;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

/**
 * This sample demonstrates how one can perform the following operations while leveraging the
 * Custom Key Attributes feature:  Key Generation, and Key Import.
 */
public class KeyAttributesRunner {

    public static void main(String[] args) throws Exception {
        try {
            if (Security.getProvider(HsmProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new HsmProvider());
            }
        } catch (IOException ex) {
            System.err.println(ex);
            return;
        }

        generateEcKeyPair();
        importAesKey();
    }

    /*
     * Demonstrate the generation of an EC key pair while using Custom Key Attributes.
     */
    private static void generateEcKeyPair() throws Exception {
        System.out.println("Generate EC Key Pair using CloudHsm Attributes\n");
        final KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC", HsmProvider.PROVIDER_NAME);

        // Demonstrate the construction of a KeyAttributesMap for the public key by first
        // instantiating the class and adding key-value pairs, much like would be done via
        // Map objects.
        final String ecPublicKeyLabel = "EC Public Key";

        final KeyAttributesMap publicKeyAttrsMap = new KeyAttributesMap();
        publicKeyAttrsMap.put(KeyAttribute.LABEL, ecPublicKeyLabel);
        publicKeyAttrsMap.put(KeyAttribute.EC_PARAMS, EcParams.EC_CURVE_PRIME256);

        // Demonstrate the construction of a KeyAttributesMap for the private key using
        // the Builder pattern.  Note how method chaining is supported.
        final String ecPrivateKeyLabel = "EC Private Key";

        final KeyAttributesMap privateKeyAttrsMap = new KeyAttributesMapBuilder()
                .put(KeyAttribute.LABEL, ecPrivateKeyLabel)
                .build();

        // Instantiate KeyPairAttributesMap for use during generation of the EC key pair.
        // Note how the Builder pattern is used to construct a KeyPairAttributesMap from
        // the previous public and private key attributes maps.
        final KeyPairAttributesMap spec = new KeyPairAttributesMapBuilder()
                .withPublic(publicKeyAttrsMap)
                .withPrivate(privateKeyAttrsMap)
                .build();
        keyPairGen.initialize(spec);
        final KeyPair keyPair = keyPairGen.generateKeyPair();
        System.out.println("EC Key Pair generated\n");
    }

    /*
     * Demonstrate the import of an externally-generated AES key while using Custom Key
     * Attributes.
     */
    private static void importAesKey() throws Exception {
        System.out.println("Importing AES Key into the HSM using CloudHsm Attributes\n");

        final int aesKeySize = 256;

        // Generate a key using the SunJCE provider.
        final KeyGenerator keyGen = KeyGenerator.getInstance("AES", "SunJCE");
        keyGen.init(aesKeySize);
        final SecretKey sk = keyGen.generateKey();

        // Import the key into the HSM.
        final String genericSecretKeyLabel = "AES Key";

        // Instantiate KeyAttributesMap for use during import of the Generic
        // Secret key.
        final KeyAttributesMap keyAttrsMap = new KeyAttributesMapBuilder()
                .put(KeyAttribute.LABEL, genericSecretKeyLabel)
                .put(KeyAttribute.VALUE, sk.getEncoded())
                .build();

        SecretKeyFactory factory = SecretKeyFactory.getInstance("AES", HsmProvider.PROVIDER_NAME);
        SecretKey cloudHsmKey = factory.generateSecret(keyAttrsMap);
        System.out.println("AES Key imported\n");
    }
}
