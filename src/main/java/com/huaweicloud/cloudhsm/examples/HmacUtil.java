// 转译自源示例（版权见记录文件）；JCE 算法流程保留，provider 适配 DEW。
package com.huaweicloud.cloudhsm.examples;

import com.huaweicloud.cloudhsm.jce.provider.HsmProvider;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import javax.crypto.Mac;

class HmacUtil {
    static byte[] hmacDigest(Key hmacKey, String algorithm, String message)
        throws GeneralSecurityException {
        Mac mac = Mac.getInstance(algorithm, HsmProvider.PROVIDER_NAME);
        mac.init(hmacKey);

        return mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
    }

    private HmacUtil() {}
}
