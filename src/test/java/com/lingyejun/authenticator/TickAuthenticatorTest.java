package com.lingyejun.authenticator;


import org.junit.Test;
import com.lingyejun.authenticator.TickAuthenticatorConfig.AuthenticatorConfigBuilder;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;

/**
 * 测试类
 *
 * @Author: lingyejun
 * @Date: 2019/2/19
 * @Describe:
 * @Modified By:
 */
public class TickAuthenticatorTest {

    private long t0 = 0;

    private long x = 30;

    private static String hash(String content) {
        StringBuffer hexString = new StringBuffer();
        try {
            MessageDigest md = MessageDigest.getInstance("HmacSHA1");
            md.update(content.getBytes());
            byte[] hash = md.digest();
            for (int i = 0; i < hash.length; i++) {
                if ((0xff & hash[i]) < 0x10) {
                    hexString.append("0" + Integer.toHexString((0xFF & hash[i])));
                } else {
                    hexString.append(Integer.toHexString(0xFF & hash[i]));
                }
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return hexString.toString();
    }

    @Test
    public void getDigest() {
        byte[] hmacResult = null;
        try {
            // 获取Hmac实例并指定其摘要算法
            Mac mac = Mac.getInstance("HmacSHA1");
            SecretKeySpec macKey = new SecretKeySpec("lingyejun".getBytes(), "HmacSHA1");
            mac.init(macKey);

            // 计算HMac结果
            hmacResult = mac.doFinal("123".getBytes());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void sampleTest() {
        AuthenticatorConfigBuilder configBuilder = new AuthenticatorConfigBuilder();
        int digit = 6;
        long timeStep = 30;
        String secret = "1";
        // 测试Key
        byte[] key = CommonUtil.hexStr2Bytes(secret);
        configBuilder.setDigit(digit).setTimeStepMills(TimeUnit.SECONDS.toMillis(timeStep));
        TickAuthenticator ta = new TickAuthenticator(configBuilder.build());
        assertEquals(ta.generateAuthCode(key, 59L / timeStep), 112887);
    }

    @Test
    public void rfc6238TestSha1() {
        // Seed for HMAC-SHA1 - 20 bytes
        String seed = "3132333435363738393031323334353637383930";
        long testTime[] = {59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L};
        long exceptedValue[] = {94287082, 7081804, 14050471, 89005924, 69279037, 65353130};
        byte[] key = CommonUtil.hexStr2Bytes(seed);
        AuthenticatorConfigBuilder configBuilder = new AuthenticatorConfigBuilder();
        configBuilder.setDigit(8).setTimeStepMills(TimeUnit.SECONDS.toMillis(x));
        TickAuthenticator ta = new TickAuthenticator(configBuilder.build());

        for (int i = 0; i < testTime.length; i++) {
            assertEquals(ta.generateAuthCode(key, (testTime[i] - t0) / x), exceptedValue[i]);
        }

        printTestResult(key, ta, configBuilder.build().getHmacType(), testTime);
    }

    @Test
    public void rfc6238TestSha256() {
        // Seed for HMAC-SHA256 - 32 bytes
        String seed32 = "3132333435363738393031323334353637383930" +
                "313233343536373839303132";
        long testTime[] = {59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L};
        long exceptedValue[] = {46119246, 68084774, 67062674, 91819424, 90698825, 77737706};
        byte[] key = CommonUtil.hexStr2Bytes(seed32);

        AuthenticatorConfigBuilder configBuilder = new AuthenticatorConfigBuilder();
        configBuilder.setDigit(8).setTimeStepMills(TimeUnit.SECONDS.toMillis(x)).setHmacType(HmacHashFunction.HmacSHA256.getHmacType());
        TickAuthenticator ta = new TickAuthenticator(configBuilder.build());

        for (int i = 0; i < testTime.length; i++) {
            assertEquals(ta.generateAuthCode(key, (testTime[i] - t0) / x), exceptedValue[i]);
        }

        printTestResult(key, ta, configBuilder.build().getHmacType(), testTime);
    }

    @Test
    public void rfc6238TestSha512() {
        // Seed for HMAC-SHA512 - 64 bytes
        String seed64 = "3132333435363738393031323334353637383930" +
                "3132333435363738393031323334353637383930" +
                "3132333435363738393031323334353637383930" +
                "31323334";
        long testTime[] = {59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L};
        long exceptedValue[] = {90693936, 25091201, 99943326, 93441116, 38618901, 47863826};
        byte[] key = CommonUtil.hexStr2Bytes(seed64);

        AuthenticatorConfigBuilder configBuilder = new AuthenticatorConfigBuilder();
        configBuilder.setDigit(8).setTimeStepMills(TimeUnit.SECONDS.toMillis(x)).setHmacType(HmacHashFunction.HmacSHA512.getHmacType());
        TickAuthenticator ta = new TickAuthenticator(configBuilder.build());

        for (int i = 0; i < testTime.length; i++) {
            assertEquals(ta.generateAuthCode(key, (testTime[i] - t0) / x), exceptedValue[i]);
        }

        printTestResult(key, ta, configBuilder.build().getHmacType(), testTime);
    }

    @Test
    public void createCredentials() {
        AuthenticatorConfigBuilder configBuilder = new AuthenticatorConfigBuilder();
        configBuilder.setDigit(8).setTimeStepMills(TimeUnit.SECONDS.toMillis(x)).setHmacType(HmacHashFunction.HmacSHA512.getHmacType());
        TickAuthenticator ta = new TickAuthenticator(configBuilder.build());

        TickAuthenticatorKey authenticatorKey = ta.createCredentials();

        String secretKey = authenticatorKey.getKey();

        int verificationCode = authenticatorKey.getVerificationCode();

        List<Integer> scratchList = authenticatorKey.getScratchList();

        System.out.println("secretKey : " + secretKey);

        System.out.println("verificationCode : " + verificationCode);

        for (Integer scratchCode : scratchList) {

            // 可见次数就碰撞到了正确的OTP密码，说明算法有问题
            if (verificationCode == scratchCode) {
                throw new IllegalArgumentException("scratch test failed，system bug.");
            }
            System.out.println(scratchCode);
        }

    }

    @Test
    public void authorize() {
        AuthenticatorConfigBuilder configBuilder = new AuthenticatorConfigBuilder();
        configBuilder.setDigit(8).setTimeStepMills(TimeUnit.SECONDS.toMillis(x)).setHmacType(HmacHashFunction.HmacSHA512.getHmacType());
        TickAuthenticator ta = new TickAuthenticator(configBuilder.build());

        String secretKey = ta.createCredentials().getKey();
        int clientCode = ta.getTimeBasedPassword(secretKey);

        boolean authFlg = ta.authorize(secretKey, clientCode);

        System.out.println("secret key : " + secretKey + " client code : " + clientCode + " authorize result : " + authFlg);
    }


    private void printTestResult(byte[] key, TickAuthenticator ta, String mode, long[] testTime) {
        String steps = "0";

        DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        df.setTimeZone(TimeZone.getTimeZone("UTC"));
        System.out.println("+---------------+-----------------------+------------------+--------+--------------+");
        System.out.println("|  Time(sec)    |   Time (UTC format)   | Value of T(Hex)  |  TOTP  |      Mode    |");
        System.out.println("+---------------+-----------------------+------------------+--------+--------------+");
        for (int i = 0; i < testTime.length; i++) {
            long T = (testTime[i] - t0) / x;
            steps = Long.toHexString(T).toUpperCase();
            while (steps.length() < 16) steps = "0" + steps;
            String fmtTime = String.format("%1$-11s", testTime[i]);
            String utcTime = df.format(new Date(testTime[i] * 1000));
            System.out.print("|  " + fmtTime + "  |  " + utcTime + "  | " + steps + " |");
            System.out.println(ta.generateAuthCode(key, (testTime[i] - t0) / x) + "| " + mode + "   |");
        }
        System.out.println("+---------------+-----------------------+------------------+--------+--------------+");
    }
}
