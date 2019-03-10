package com.lingyejun.authenticator;

/**
 * @Author: lingyejun
 * @Date: 2019/2/20
 * @Describe:
 * @Modified By:
 */
public enum HmacHashFunction {

    HmacSHA1("HmacSHA1"),
    HmacSHA256("HmacSHA256"),
    HmacSHA512("HmacSHA512");

    private String hmacType;

    HmacHashFunction(String hmacType) {
        this.hmacType = hmacType;
    }

    public String getHmacType() {
        return hmacType;
    }

    public static boolean isLegalType(String hmacType) {

        boolean legalFlg = false;

        for (HmacHashFunction hmacTypeEnum : HmacHashFunction.values()) {
            if (hmacTypeEnum.hmacType.equals(hmacType)) {
                legalFlg = true;
                break;
            }
        }
        return legalFlg;
    }
}
