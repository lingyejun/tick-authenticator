package com.lingyejun.authenticator.tick;

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
        for(int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(bytes[i] & 0xFF);
            if(hex.length() < 2){
                buffer.append(0);
            }
            buffer.append(hex);
        }
        return buffer.toString();
    }

    public static void main(String[] args) {
        byte[] bytes = new byte[]{34 ,112, -98, 94, 34, -56, 0, 8, -21, 11, 35, -73, -18, -111, 80, -74, 31, 119, -11, -34};
        System.out.println(bytesToHexString(bytes));
    }


}
