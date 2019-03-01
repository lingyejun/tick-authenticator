package com.lingyejun.authenticator.tick;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * TickAuthenticator
 *
 * @Author: lingyejun
 * @Date: 2019/2/24
 * @Describe: 
 * @Modified By:
 */
public class TickAuthenticator implements ITickAuthenticator{

    private static final Logger LOGGER = Logger.getLogger(TickAuthenticator.class.getName());

    // 32位int用十六进制表示的最大值
    private static final int MAX_HEX_INTEGER = 0x7FFFFFFF;

    // 配置项类
    private final TickAuthenticatorConfig config;

    public TickAuthenticator() {
        config = new TickAuthenticatorConfig();
    }

    public int generateAuthCode(byte[] key, long value){

        // 为64位long类型创建byte[]
        byte[] data = new byte[8];
        // 转为8字节64位的字节数组

        // 初始化秘钥
        SecretKey secretKey = new SecretKeySpec(key, HmacTypeEnum.HmacSHA1.getHmacType());

        try {
            // 获取Hmac实例并指定其摘要算法
            Mac mac = Mac.getInstance(HmacTypeEnum.HmacSHA1.getHmacType());
            mac.init(secretKey);

            // 计算HMac结果
            byte[] hmacResult = mac.doFinal(data);

            // 取数组末端低四位并计算偏移量offset
            int offset = hmacResult[hmacResult.length - 1] & 0xF;

            long truncation = 0;

            // 从偏移位置开始取4个字节作为OTP基础数据
            for (int i = 0; i < 4; i++) {
                // 将上一个字节数据左移
                truncation <<= 8;

                // 与此字节进行拼接
                truncation |= hmacResult[offset + i] & 0xFF;
            }
            // 截取低32位的数据
            truncation &= MAX_HEX_INTEGER;

            // 截取要返回长度的数据
            truncation %= config.getModDigit();

            return (int)truncation;

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {

            LOGGER.log(Level.SEVERE, e.getMessage(), e);

            throw new TickAuthenticatorException("generated auth code throws exception");
        }

    }
}
