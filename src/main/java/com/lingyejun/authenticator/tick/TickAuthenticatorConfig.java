package com.lingyejun.authenticator.tick;

/**
 * @Author: lingyejun
 * @Date: 2019/2/22
 * @Describe: 
 * @Modified By:
 */
public class TickAuthenticatorConfig {

    // OTP长度
    private int digit = 6;

    // 用于取模计算的基数
    private int modDigit = (int) Math.pow(10, digit);

    public int getDigit() {
        return digit;
    }

    public void setDigit(int digit) {
        this.digit = digit;
    }

    public int getModDigit() {
        return modDigit;
    }

    public void setModDigit(int modDigit) {
        this.modDigit = modDigit;
    }
}
