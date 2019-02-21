package com.lingyejun.authenticator.tick;

/**
 * @Author: lingyejun
 * @Date: 2019/2/20
 * @Describe:
 * @Modified By:
 */
public enum HmacTypeEnum {

    HmacSHA1("SHA1"),
    HmacSHA256("SHA256"),
    HmacSHA512("SHA512");

    private String hmacType;

    HmacTypeEnum(String hmacType) {
        this.hmacType = hmacType;
    }

    public String getHmacType() {
        return hmacType;
    }

}
