# tick-authenticator

Time-based One-time Password (TOTP) algorithm specified in RFC 6238.

生活中我们会经常使用到TOTP的算法应用，如银行的动态口令器、网络游戏中的将军令、登录场景下的手机二次验证等等。

下图便是一个常见的TOTP动态密码生成器：

![otp-prover](https://github.com/lingyejun/tick-authenticator/blob/master/doc/ref/img/otp-prover.png)

为了提高游戏账号的安全性我们在输入账号密码后，对于绑定了将军令的用户还需要输入将军令（OTP动态口令生成器）上面的一次性动态密码，验证通过后方才登陆成功。

![demo-login](https://github.com/lingyejun/tick-authenticator/blob/master/doc/ref/img/demo-login.jpeg)

# TOTP的生成步骤

## RFC4226中定义了生成HOTP的关键三个步骤

* Step 1: Generate an HMAC-SHA-1 value Let HS = HMAC-SHA-1(K,C)  // HS is a 20-byte string

* Step 2: Generate a 4-byte string (Dynamic Truncation)
Let Sbits = DT(HS)   //  DT, defined below,
                     //  returns a 31-bit string

The Truncate function performs Step 2 and Step 3, i.e., the dynamic truncation and then the reduction modulo 10^Digit.  The purpose of the dynamic offset truncation technique is to extract a 4-byte dynamic binary code from a 160-bit (20-byte) HMAC-SHA-1 result.  

DT(String) // String = String[0]...String[19]
Let OffsetBits be the low-order 4 bits of String[19]  
Offset = StToNum(OffsetBits) // 0 <= OffSet <= 15  
Let P = String[OffSet]...String[OffSet+3]  
Return the Last 31 bits of P

* Step 3: Compute an HOTP value
Let Snum  = StToNum(Sbits)   // Convert S to a number in 0...2^{31}-1
Return D = Snum mod 10^Digit //  D is a number in the range 0...10^{Digit}-1

## RFC6238中关于生成TOTP的描述

* HOTP(K,C) = Truncate(HMAC-SHA-1(K,C))

* Basically, we define TOTP as TOTP = HOTP(K, T), where T is an integer and represents the number of time steps between the initial counter time T0 and the current Unix time.

* X represents the time step in seconds (default value X = 30 seconds) and is a system parameter.
      
* T0 is the Unix time to start counting time steps (default value is 0, i.e., the Unix epoch) and is also a system parameter.
         
* T = (Current Unix time - T0) / X, where the default floor function is used in the computation.


# 实例讲述TOTP的算法流程

![totp-easy](https://github.com/lingyejun/tick-authenticator/blob/master/doc/ref/img/totp-desc-esay.png)
    
## 六位TOTP动态密钥的计算过程

T = (Current Unix time - T0) / X

For example, T0 = 1550986201000, current unix time = 1550986260000 and X = 30000 in millisecond.

T = (1550986260000 - 1550986201000) / 30000 = 1

value = 1 and type is long.

long --> byte[32]

1 --> [0000 0000 0000 0000 0000 0001]

key : 1

SHA-1 HMAC Bytes (Example)

HmacSHA1(key,value) = [34 112 -98 94 34 -56 0 8 -21 11 35 -73 -18 -111 80 -74 31 119 -11 -34]  
                    = [22 70 9e 5e 22 c8 00 08 eb 0b 23 b7 ee 91 50 b6 1f 77 f5 de]  
                    

```

   -------------------------------------------------------------
   | Byte Number                                               |
   -------------------------------------------------------------
   |00|01|02|03|04|05|06|07|08|09|10|11|12|13|14|15|16|17|18|19|
   -------------------------------------------------------------
   | Byte Value                                                |
   -------------------------------------------------------------
   |22|70|9e|5e|22|c8|00|08|eb|0b|23|b7|ee|91|50|b6|1f|77|f5|de|
   ------------------------------------------*************---++|
   
```

1. The last byte (byte 19) has the hex value 0xde.
	
	* 	hex value of 0xde convert to binary value is [1101 1110]
	*  the num 34 and binary value is [0010 0010], it's 2's complement is [1101 1110] that is -34 binary num.
	
2. The value of the lower 4 bits is 0xe (the offset value).
	
	* int offset = HS1[HS1.length -1 ] & 0xF.
	* 0xde & 0xf = 0xe.
	* [1101 1110] & [0000 1111] = [0000 1110] = 14.

3. The offset value is byte 14 (0xe).

4. The value of the 4 bytes starting at byte 14 is [50 b6 1f 77],
     which is the dynamic binary code DBC1.
	
	* We treat the dynamic binary code as a 31-bit, unsigned, big-endian
   integer; the first byte is masked with a 0x7f.     

5. The MSB of DBC1 is 0x50 so DBC2 = DBC1 = 0x50ef7f19 = 1354112887.

6. TOTP = DBC2 modulo 10^6 = 112887.

	* 1354112887 % 10^6 = 112887	
                   
