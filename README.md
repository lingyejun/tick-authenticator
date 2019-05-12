# tick-authenticator

Time-based One-time Password (TOTP) algorithm specified in RFC 6238.

生活中我们会经常使用到TOTP的算法应用，如银行的动态口令器、网络游戏中的将军令、登录场景下的手机二次验证等等。

下图便是一个常见的TOTP动态密码生成器：

![otp-prover](https://github.com/lingyejun/tick-authenticator/blob/master/doc/ref/img/otp-prover.png)

为了提高游戏账号的安全性我们在输入账号密码后，对于绑定了将军令的用户还需要输入将军令（OTP动态口令生成器）上面的一次性动态密码，验证通过后方才登陆成功。

![demo-login](https://github.com/lingyejun/tick-authenticator/blob/master/doc/ref/img/demo-login.jpeg)

# TOTP Img Description

<img src="https://github.com/lingyejun/tick-authenticator/blob/master/doc/ref/img/totp-desc.png" width = 300% height = 300% div align=center/>

# Definition of HMAC

We define two fixed and different strings ipad and opad as follows (the 'i' and 'o' are mnemonics for inner and outer):
ipad = the byte 0x36 repeated B times  
opad = the byte 0x5C repeated B times.  
  
To compute HMAC over the data ‘text' we perform  
  
H(K XOR opad, H(K XOR ipad, text))  

# Notations

* HOTP(K,C) = Truncate(HMAC-SHA-1(K,C))

* Basically, we define TOTP as TOTP = HOTP(K, T), where T is an integer
   and represents the number of time steps between the initial counter
   time T0 and the current Unix time.

* X represents the time step in seconds (default value X =
      30 seconds) and is a system parameter.
      
* T0 is the Unix time to start counting time steps (default value is
      0, i.e., the Unix epoch) and is also a system parameter.
      
      
* T = (Current Unix time - T0) / X, where the
   default floor function is used in the computation.
      
# Example of TOTP Computation for Digit = 6


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

6. HOTP = DBC2 modulo 10^6 = 112887.

	* 1354112887 % 10^6 = 112887	
                   
