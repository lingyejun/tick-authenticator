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

HmacSHA1(key,value) = [5b 0c 15 7d 4e 76 72 44 4c 41 03 35 61 55 48 39 ed 1f d2 d6]
                    = []

HS1 = HmacSHA1(key,value)

int offset = HS1[HS1.length -1 ] & 0xF

1000 0000 0000 0000 0010 0010
&
0000 0000 0000 0000 0000 1111
0000 0000 0000 0000 0000 0010

