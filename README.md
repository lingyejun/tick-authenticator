# tick-authenticator
Time-based One-time Password (TOTP) algorithm specified in RFC 6238.

# Example

IT : Initial Time
CT : Current Time
TW : Time Window

C = (CT-IT)/TW

For example 

IT = 1550986201000
CT = 1550986260000
TW = 30s = 30000 ms

C = (1550986260000 - 1550986201000) / 30000 = 1

value = 1 and type is long.

long --> byte[32]

1 --> [0000 0000 0000 0000 0000 0001]

key : 1

HmacSHA1(key,value) = [34 112 -98 94 34 -56 0 8 -21 11 35 -73 -18 -111 80 -74 31 119 -11 -34]  
                    = [22 70 9e 5e 22 c8 00 08 eb 0b 23 b7 ee 91 50 b6 1f 77 f5 de]  
                    

HS1 = HmacSHA1(key,value)

int offset = HS1[HS1.length -1 ] & 0xF

34 = 0010 0010  
-34 = 1101 1110  

1101 1110  
&  
0000 1111  
0000 1110  
=14  

HS1[14...17] = [50 b6 1f 77] = [80 -74 31 119]  
  
--> 1354112887  

1354112887 % 10^6 = 54112887  
  
result = 54112887  
