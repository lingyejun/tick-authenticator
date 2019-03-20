package com.lingyejun.authenticator;

import com.sun.xml.internal.rngom.parse.host.Base;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;

/**
 * TOTP实现类
 *
 * @Author: lingyejun
 * @Date: 2019/2/24
 * @Describe: 
 * @Modified By:
 */
public class TickAuthenticator implements ITickAuthenticator{

    private static final Logger LOGGER = Logger.getLogger(TickAuthenticator.class.getName());

    // 密钥随机算法
    @SuppressWarnings("SpellCheckingInspection")
    private static final String RNG_ALGORITHM = "SHA1PRNG";

    // 密钥随机算法的提供方
    @SuppressWarnings("SpellCheckingInspection")
    private static final String RNG_ALGORITHM_PROVIDER = "SUN";

    // 初始化密钥随机
    private final TickSecureRandom tickSecureRandom = new TickSecureRandom(RNG_ALGORITHM, RNG_ALGORITHM_PROVIDER);

    // 32位int用十六进制表示的最大值
    private static final int MAX_HEX_INTEGER = 0x7FFFFFFF;

    // 秘钥的二进制长度
    private static final int SECRET_BITS_LENGTH = 80;

    // 配置项类
    private final TickAuthenticatorConfig config;

    public TickAuthenticator() {
        config = new TickAuthenticatorConfig();
    }

    public TickAuthenticator(TickAuthenticatorConfig config) {
        this.config = config;
    }

    public int generateAuthCode(byte[] key, long tm){

        // 为64位long类型创建byte[]
        byte[] data = new byte[8];

        long value = tm;

        // 将long转为8字节64位的字节数组
        for (int i = 8; i-- > 0; value >>>= 8) {
            // 记录低八位后右移
            data[i] = (byte) value;
        }

        // 初始化秘钥
        SecretKey secretKey = new SecretKeySpec(key, config.getHmacType());

        try {
            // 获取Hmac实例并指定其摘要算法
            Mac mac = Mac.getInstance(config.getHmacType());
            mac.init(secretKey);

            // 计算HMac结果
            byte[] hmacResult = mac.doFinal(data);

            // 取数组末端低四位并计算偏移量offset
            int offset = hmacResult[hmacResult.length - 1] & 0xF;

            // 从偏移位置开始取4个字节作为OTP基础数据
            long truncation = (hmacResult[offset]  & 0x7f) << 24
                    | (hmacResult[offset+1] & 0xff) << 16
                    | (hmacResult[offset+2] & 0xff) <<  8
                    | (hmacResult[offset+3] & 0xff) ;

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

    /**
     * 生成客户端凭证
     *
     * @return
     */
    @Override
    public TickAuthenticatorKey createCredentials() {
        // 分配随机数空间
        byte[] bytes = new byte[SECRET_BITS_LENGTH];
        // 填充随机数
        tickSecureRandom.filledRandomBytes(bytes);
        // 生成用户可见的密钥
        String userViewkey =

        return null;
    }

    /**
     * 将密钥转换为可见的形式
     *
     * @param randomBytes
     * @return
     */
    private String converterSecretKey(byte[] randomBytes) {
        switch (config.getSecretKeyEncoding()){
            case "Base32":
                return new Base32().encodeToString(randomBytes);
            case "Base64":
                return new Base64().encodeToString(randomBytes);
            default:
                throw new IllegalArgumentException("not support converter encoding type");
        }
    }
}
