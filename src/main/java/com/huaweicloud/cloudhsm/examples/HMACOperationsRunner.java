// 转译自源示例（版权见记录文件）；JCE 算法流程保留，provider 适配 DEW。
package com.huaweicloud.cloudhsm.examples;

import com.huaweicloud.cloudhsm.jce.provider.HsmProvider;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Base64;
import javax.crypto.Mac;

/**
 * Demonstrate basic HMAC operation.
 */
public class HMACOperationsRunner {

    /**
     * Digest a message using the passed algorithm.
     * Supported digest types are documented here: https://support.huaweicloud.com/api-cloudhsm/
     *
     * @param message
     * @param key
     * @param algorithm
     * @param provider
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static byte[] digest(byte[] message, Key key, String algorithm, String provider)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        Mac mac = Mac.getInstance(algorithm, provider);
        mac.init(key);
        mac.update(message);
        return mac.doFinal();
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

        Key key = SymmetricKeys.generateHmacKey("HmacTest");
        String algorithm = "HmacSHA1";

        byte[] cloudHsmDigest = digest(plainText.getBytes("UTF-8"), key, algorithm, HsmProvider.PROVIDER_NAME);
        System.out.println("CloudHSM HMAC= " + Base64.getEncoder().encodeToString(cloudHsmDigest));
    }
}
