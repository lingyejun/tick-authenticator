package com.lingyejun.authenticator;

/**
 * SecretKey的编码方式枚举
 *
 * @Author: lingyejun
 * @Date: 2019/3/18
 * @Describe:
 * @Modified By:
 */
public enum SecretKeyEncoding {

    Base32,
    Base64;

    public static boolean isLegal(String secretKeyEncoding) {
        boolean legalFlg = false;

        for (SecretKeyEncoding encoding : SecretKeyEncoding.values()) {
            if (encoding.toString().equals(secretKeyEncoding)) {
                legalFlg = true;
                break;
            }
        }
        return legalFlg;
    }
}
