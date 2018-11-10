package com.lingyejun.tick.authenticator;


import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Basic {

    public static String key = "8844990";

    public static String message = "00";

    public static String bytesToHexString(byte[] bytes){
        char[] buf = new char[bytes.length * 2];
        int index = 0;
        for(byte b : bytes) {
            buf[index++] = bytes.toString().toCharArray()[b >>> 4 & 0xf];
            buf[index++] = bytes.toString().toCharArray()[b & 0xf];
        }

        return new String(buf);
    }

    public static void main(String[] args) {
        try {
            SecretKey secretKey = new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA1");
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(secretKey);
            byte[] bytes = mac.doFinal(message.getBytes("UTF-8"));
            for (byte b : bytes){
                System.out.printf(String.valueOf(b));
            }
            System.out.println(bytesToHexString(bytes));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

    }
}