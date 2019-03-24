package com.lingyejun.authenticator;

/**
 * TickAuthenticator接口
 *
 * @Author: lingyejun
 * @Date: 2019/2/18
 * @Describe: TickAuthenticator Interface
 * @Modified By:
 */
public interface ITickAuthenticator {

    /**
     * 生成客户端凭证
     *
     * @return 密钥对象
     */
    TickAuthenticatorKey createCredentials();

    /**
     * 基于客户端当前时间获取TOTP密码
     *
     * @param secretKey 密钥
     * @return 动态totp验证码
     */
    int getTimeBasedPassword(String secretKey);

    /**
     * 基于指定时间获取TOTP密码
     *
     * @param secretKey 密钥
     * @param timestamp 指定时间戳
     * @return 动态totp验证码
     */
    int getTimeBasedPassword(String secretKey, long timestamp);

    /**
     * 使用服务器当前时间的时间戳来验证客户端一次性密码是否正确
     *
     * @param secret 密钥
     * @param clientCode 客户端的一次性密码
     * @return 验证通过则为true
     */
    boolean authorize(String secret, int clientCode);

    /**
     * 使用指定时间戳来验证客户端一次性密码是否正确
     * 将客户端的漂移时间记录下来，针对不同的客户端使用符合各自时间误差的时间戳，起到自动校准纠正的功能。
     *
     * @param secret 密钥
     * @param clientCode 客户端的一次性密码
     * @param timestamp 当前时间戳
     * @return 验证通过则为true
     */
    boolean authorize(String secret, int clientCode, long timestamp);
}
