package com.lingyejun.authenticator;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 生成随机秘钥
 *
 * @Author: lingyejun
 * @Date: 2019/3/18
 * @Describe:
 * @Modified By:
 */
public class TickSecureRandom {

    /**
     * 随机算法
     */
    private final String algorithm;

    /**
     * 算法提供方
     */
    private final String provider;

    /**
     * 强随机数生成器
     */
    private volatile SecureRandom secureRandom;

    /**
     * 原子型Integer,初始化计数起点
     */
    private final AtomicInteger count = new AtomicInteger(0);

    /**
     * 周期动态生成新的随机数生成器(每1000个换一次新的随机)
     */
    private static final int DYNAMIC_REBUILD_SECRET = 1_000;

    public TickSecureRandom(String algorithm, String provider) {

        if (algorithm == null) {
            throw new IllegalArgumentException("secure random algorithm not be nul");
        }

        if (provider == null) {
            throw new IllegalArgumentException("secure random provider not be nul");
        }

        this.algorithm = algorithm;
        this.provider = provider;

        buildSecureRandom();
    }

    /**
     * 构建密钥随机种子生成器
     */
    public void buildSecureRandom() {

        try {

            if (algorithm == null && provider == null) {

                this.secureRandom = new SecureRandom();

            } else if (provider == null) {

                this.secureRandom = SecureRandom.getInstance(algorithm);

            } else {

                this.secureRandom = SecureRandom.getInstance(algorithm, provider);

            }
        } catch (NoSuchAlgorithmException e) {

            throw new TickAuthenticatorException("secure random algorithm" + algorithm + " is not support", e);

        } catch (NoSuchProviderException e) {

            throw new TickAuthenticatorException("secure random provide" + provider + "is not support", e);

        }
    }

    /**
     * 生成随机密钥
     *
     * @param bytes 待填充的数组
     */
    public void filledRandomBytes(byte[] bytes) {

        // 生成一定数量随机密钥后，刷新SecureRandom
        if (count.incrementAndGet() > DYNAMIC_REBUILD_SECRET) {
            // 防止恶意的并发请求而导致的不刷新
            synchronized (this) {
                // 是否有其他线程已经重置了
                if (count.get() > DYNAMIC_REBUILD_SECRET) {
                    // 根据不可预知的事件种子，重新生成随机算法
                    buildSecureRandom();
                    // 重置
                    count.set(0);
                }
            }
        }
        // filled in with random bytes
        secureRandom.nextBytes(bytes);
    }
}
