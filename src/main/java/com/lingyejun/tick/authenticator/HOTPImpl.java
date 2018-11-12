package com.lingyejun.tick.authenticator;

public class HOTPImpl {

    /**
     * Generate an HMAC-SHA-1 value
     * Let HS = HMAC-SHA-1(K,C) and HS is a 20-byte string
     *
     * @param key
     * @param count
     * @return
     */
    private byte[] getHmacValue(String key,String count){

    }

    /**
     * Generate a 4-byte string (Dynamic Truncation)
     * Let Sbits = DT(HS)   //  DT, defined below, //  returns a 31-bit string
     *
     * @param source
     * @return
     */
    private byte[] dynamicTruncate(byte[] source){

    }

    /**
     * Compute an HOTP value
     *
     * @param key
     * @param count
     * @return
     */
    public String getDigitPwd(String key,String count){


    }

    public static void main(String[] args) {
        
    }
}
