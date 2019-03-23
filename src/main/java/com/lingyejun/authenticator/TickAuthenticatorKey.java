package com.lingyejun.authenticator;

import java.util.List;

/**
 * 秘钥Key配置
 *
 * @Author: lingyejun
 * @Date: 2019/2/23
 * @Describe: 
 * @Modified By:
 */
public class TickAuthenticatorKey {

    /**
     * 配置类
     */
    private final TickAuthenticatorConfig config;

    /**
     * 基于Base编码过后的Key
     */
    private final String key;

    /**
     * 验证码，从Unix epoch的0时刻开始
     */
    private final int verificationCode;

    /**
     * 用于进行碰撞验证，检测可用性
     */
    private final List<Integer> scratchList;

    public TickAuthenticatorKey(TickAuthenticatorConfig config, String key, int verificationCode, List<Integer> scratchList) {
        this.config = config;
        this.key = key;
        this.verificationCode = verificationCode;
        this.scratchList = scratchList;
    }

    public TickAuthenticatorConfig getConfig() {
        return config;
    }

    public String getKey() {
        return key;
    }

    public int getVerificationCode() {
        return verificationCode;
    }

    public List<Integer> getScratchList() {
        return scratchList;
    }
}
