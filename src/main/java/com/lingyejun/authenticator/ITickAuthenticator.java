package com.lingyejun.authenticator;

/**
 * @Author: lingyejun
 * @Date: 2019/2/18
 * @Describe: TickAuthenticator Interface
 * @Modified By:
 */
public interface ITickAuthenticator {

    /**
     * 生成客户端凭证
     *
     *
     *
     * @return
     */
    TickAuthenticatorKey createCredentials();
}
