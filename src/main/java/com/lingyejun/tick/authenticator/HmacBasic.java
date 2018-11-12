package com.lingyejun.tick.authenticator;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import org.apache.commons.codec.binary.Hex;

public class HmacBasic {

    public static String key = "8844990";

    public static String message = "lingyejun";

    public static final String HMAC_TYPE = "HmacSHA1";

    public static final String BYTE_ENCODE = "UTF-8";

    public static byte[] generateHashValue

    public static void main(String[] args) {
        try {
            SecretKey secretKey = new SecretKeySpec(key.getBytes(BYTE_ENCODE), HMAC_TYPE);
            Mac mac = Mac.getInstance(HMAC_TYPE);
            mac.init(secretKey);
            byte[] bytes = mac.doFinal(message.getBytes(BYTE_ENCODE));
            System.out.println(new String(bytes));
            byte[] hexBytes = new Hex().encode(bytes);
            System.out.println(new String(hexBytes));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

    }
}