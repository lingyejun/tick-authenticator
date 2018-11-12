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
        return HmacBasic.getHmacSha1Value(key,count);
    }

    /**
     * Generate a 4-byte string (Dynamic Truncation)
     * Let Sbits = DT(HS)   //  DT, defined below, //  returns a 31-bit string
     *
     * @param source
     * @return
     */
    private int dynamicTruncate(byte[] source){
        int offset = source[19] & 0xf ;
        int binCode = (source[offset]  & 0x7f) << 24
                | (source[offset+1] & 0xff) << 16
                | (source[offset+2] & 0xff) <<  8
                | (source[offset+3] & 0xff) ;
        return binCode;
    }

    /**
     * Compute an HOTP value
     *
     * @param key
     * @param count
     * @return
     */
    public String getDigitPwd(String key,String count,int digit){
        //System.out.println(dynamicTruncate(new byte[]{50,ef,7f,19}));
        int otp = dynamicTruncate(getHmacValue(key, count)) % (10 ^ digit);
        String result = Integer.toString(otp);
        return result;
    }

    public static void main(String[] args) {
        HOTPImpl hotp = new HOTPImpl();
        System.out.println();
        System.out.println(hotp.getDigitPwd("8844990","9900888090099009",6));
    }
}
