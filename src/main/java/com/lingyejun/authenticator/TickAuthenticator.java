package com.lingyejun.authenticator;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
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
public class TickAuthenticator implements ITickAuthenticator {

    private static final Logger LOGGER = Logger.getLogger(TickAuthenticator.class.getName());

    /**
     * 密钥随机算法
     */
    @SuppressWarnings("SpellCheckingInspection")
    private static final String RNG_ALGORITHM = "SHA1PRNG";

    /**
     * 密钥随机算法的提供方
     */
    @SuppressWarnings("SpellCheckingInspection")
    private static final String RNG_ALGORITHM_PROVIDER = "SUN";

    /**
     * 用于计算碰撞码的随机字节长度
     */
    private static final int BYTES_PER_SCRATCH_CODE = 4;

    /**
     * 碰撞码长度
     */
    private static final int SCRATCH_CODE_LENGTH = 8;

    /**
     * 计算碰撞码时的模
     */
    private static final int SCRATCH_CODE_MODULUS = (int) Math.pow(10, SCRATCH_CODE_LENGTH);

    /**
     * 初始化密钥随机
     */
    private final TickSecureRandom tickSecureRandom = new TickSecureRandom(RNG_ALGORITHM, RNG_ALGORITHM_PROVIDER);

    /**
     * 32位int用十六进制表示的最大值
     */
    private static final int MAX_HEX_INTEGER = 0x7FFFFFFF;

    /**
     * 秘钥的二进制长度
     */
    private static final int SECRET_BITS_LENGTH = 80;

    /**
     * 配置项类
     */
    private final TickAuthenticatorConfig config;

    public TickAuthenticator(TickAuthenticatorConfig config) {
        this.config = config;
    }

    /**
     * 根据key和time生成验证码
     *
     * @param key 字节数组密钥
     * @param tm 用于计算的当前窗口
     * @return 验证码
     */
    public int generateAuthCode(byte[] key, long tm) {

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
            long truncation = (hmacResult[offset] & 0x7f) << 24
                    | (hmacResult[offset + 1] & 0xff) << 16
                    | (hmacResult[offset + 2] & 0xff) << 8
                    | (hmacResult[offset + 3] & 0xff);

            // 截取低32位的数据
            truncation &= MAX_HEX_INTEGER;

            // 截取要返回长度的数据
            truncation %= config.getModDigit();

            return (int) truncation;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {

            LOGGER.log(Level.SEVERE, e.getMessage(), e);

            throw new TickAuthenticatorException("generated auth code throws exception");
        }

    }

    /**
     * 验证一次性密码
     *
     * @param secretKey 密钥
     * @param clientCode 用户输入的一次性密码
     * @param timestamp 服务器的时间戳
     * @param driftWindowSize 漂移窗口的大小
     * @return 验证成功则为true
     */
    private boolean authorizeCode(String secretKey, long clientCode, long timestamp, int driftWindowSize) {

        // 密钥解码
        byte[] bytes = decodeSecret(secretKey);

        // 获取当前的时间窗口
        final long currentWindow = getCurrentTimeWindow(timestamp);

        // 窗口容错以保证服务端和客户端始终不同步而导致误判
        for (int i = -((driftWindowSize - 1) / 2); i < (driftWindowSize) / 2; i++) {

            long serverCode = generateAuthCode(bytes, currentWindow + i);

            // 验证成功
            if (serverCode == clientCode) {
                return true;
            }
        }

        return false;
    }

    /**
     * 根据时间窗口的步长，获取当前所处的窗口
     *
     * @param timestamp 时间戳
     * @return 当前所在的窗口
     */
    private long getCurrentTimeWindow(long timestamp) {

        return timestamp / config.getTimeStepMills();
    }

    /**
     * 生成客户端凭证
     *
     * @return 密钥对象
     */
    @Override
    public TickAuthenticatorKey createCredentials() {

        // 分配随机数空间
        byte[] bytes = new byte[SECRET_BITS_LENGTH / 8];

        // 填充随机数
        tickSecureRandom.filledRandomBytes(bytes);

        // 生成用户可见的密钥
        String userViewKey = converterSecretKey(bytes);

        // 生成用于验证的码
        int validationCode = generateValidateCode(bytes);

        // 生成碰撞测试用的码
        List<Integer> scratchCodes = createScratchList();

        return new TickAuthenticatorKey(config, userViewKey, validationCode, scratchCodes);
    }

    /**
     * 基于客户端当前时间获取TOTP密码
     *
     * @param secretKey 密钥
     * @return TOTP密码
     */
    @Override
    public int getTimeBasedPassword(String secretKey) {
        return getTimeBasedPassword(secretKey, System.currentTimeMillis());
    }

    /**
     * 基于指定时间获取TOTP密码
     *
     * @param secretKey 密钥
     * @param timestamp 时间戳
     * @return TOTP密码
     */
    @Override
    public int getTimeBasedPassword(String secretKey, long timestamp) {
        return generateAuthCode(decodeSecret(secretKey), getCurrentTimeWindow(timestamp));
    }

    /**
     * 使用服务器当前时间的时间戳来验证客户端一次性密码是否正确
     *
     * @param secret     密钥
     * @param clientCode 客户端的一次性密码
     * @return 验证通过则为true
     */
    @Override
    public boolean authorize(String secret, int clientCode) {
        return authorize(secret, clientCode, System.currentTimeMillis());
    }

    /**
     * 验证客户端一次性密码是否正确
     *
     * @param secret     密钥
     * @param clientCode 客户端的一次性密码
     * @param timestamp  当前时间戳
     * @return 验证通过则为true
     */
    @Override
    public boolean authorize(String secret, int clientCode, long timestamp) {

        if (secret == null || secret.isEmpty()) {
            throw new IllegalArgumentException("secret key is not null or empty.");
        }

        if (clientCode <= 0 || clientCode > config.getModDigit()) {
            return false;
        }


        return authorizeCode(secret, clientCode, timestamp, config.getClockDriftWindow());
    }

    /**
     * 生成碰撞测试列表
     *
     * @return 碰撞List
     */
    private List<Integer> createScratchList() {
        List<Integer> list = new ArrayList<>();
        for (int i = 0; i < config.getScratchNum(); i++) {
            list.add(createScratchCode());
        }
        return list;
    }

    /**
     * 生成碰撞码
     *
     * @return 碰撞码
     */
    private int createScratchCode() {

        while (true) {
            byte[] scratchCodeBuffer = new byte[BYTES_PER_SCRATCH_CODE];
            tickSecureRandom.filledRandomBytes(scratchCodeBuffer);

            if (scratchCodeBuffer.length < BYTES_PER_SCRATCH_CODE) {
                throw new IllegalArgumentException(
                        String.format(
                                "The provided random byte buffer is too small: %d.",
                                scratchCodeBuffer.length));
            }

            int scratchCode = 0;

            for (int i = 0; i < BYTES_PER_SCRATCH_CODE; ++i) {
                scratchCode = (scratchCode << 8) + (scratchCodeBuffer[i] & 0xff);
            }

            scratchCode = (scratchCode & 0x7FFFFFFF) % SCRATCH_CODE_MODULUS;

            if (scratchCode >= SCRATCH_CODE_MODULUS / 10) {
                return scratchCode;
            }
        }
    }

    /**
     * 生成验证码
     *
     * @param secretBytes 字节数组密钥
     * @return 验证码
     */
    private int generateValidateCode(byte[] secretBytes) {
        // 基于0时刻
        return generateAuthCode(secretBytes, 0);
    }

    /**
     * 将密钥转换为可见的形式
     *
     * @param randomBytes 随机的字节数组
     * @return 可见密钥
     */
    private String converterSecretKey(byte[] randomBytes) {
        switch (config.getSecretKeyEncoding()) {
            case "Base32":
                return new Base32().encodeToString(randomBytes);
            case "Base64":
                return new Base64().encodeToString(randomBytes);
            default:
                throw new IllegalArgumentException("not support converter encoding type");
        }
    }

    /**
     * 密钥解码
     *
     * @param secretKey 编码后的密钥
     * @return 解码后密钥
     */
    private byte[] decodeSecret(String secretKey) {
        switch (config.getSecretKeyEncoding()) {
            case "Base32":
                return new Base32().decode(secretKey.toUpperCase());
            case "Base64":
                return new Base64().decode(secretKey.toUpperCase());
            default:
                throw new IllegalArgumentException("not support decode type");
        }
    }
}
