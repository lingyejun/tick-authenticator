package com.lingyejun.authenticator.tick;

import java.math.BigInteger;

/**
 * 工具类
 *
 * @Author: lingyejun
 * @Date: 2019/2/26
 * @Describe:
 * @Modified By:
 */
public class CommonUtil {

    /**
     * 字节数组转十六进制字符串
     *
     * @param bytes
     * @return
     */
    public static String bytesToHexString(byte[] bytes) {
        StringBuffer buffer = new StringBuffer();
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(bytes[i] & 0xFF);
            if (hex.length() < 2) {
                buffer.append(0);
            }
            buffer.append(hex);
        }
        return buffer.toString();
    }

    /**
     * 十六进制字符串转字节数组
     *
     * @param hex
     * @return
     */
    public static byte[] hexStr2Bytes(String hex) {

        // Adding one byte to get the right conversion
        // values starting with "0" can be converted
        byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();

        // Copy all the REAL bytes, not the "first"
        byte[] ret = new byte[bArray.length - 1];
        for (int i = 0; i < ret.length; i++)
            ret[i] = bArray[i + 1];
        return ret;
    }

    public static void main(String[] args) {
        byte[] bytes = new byte[]{34, 112, -98, 94, 34, -56, 0, 8, -21, 11, 35, -73, -18, -111, 80, -74, 31, 119, -11, -34};
        String hex = bytesToHexString(bytes);
        System.out.println(hex);
        byte[] newByte = hexStr2Bytes(hex);
        for (int i = 0; i < newByte.length; i++) {
            System.out.print(newByte[i] + " ");
        }
    }


}
