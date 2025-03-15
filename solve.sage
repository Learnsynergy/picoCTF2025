import zlib
from pwn import *

conn = remote("activist-birds.picoctf.net",51015)

conn.recvline()

pt1 = bytes.fromhex(conn.recvline().decode().split(":")[1].strip())
message_enc1 = bytes.fromhex(conn.recvline().decode().split(":")[1].strip())

conn.recvline()
conn.recvline()
conn.recvline()

pt2 = bytes.fromhex(conn.recvline().decode().split(":")[1].strip())
message_enc2 = bytes.fromhex(conn.recvline().decode().split(":")[1].strip())

conn.recvline()
conn.recvline()

ct1 = message_enc1[:-28]
tag1 = message_enc1[-28:-12]
nonce1 = message_enc1[-12:]

ct2 = message_enc2[:-28]
tag2 = message_enc2[-28:-12]
nonce2 = message_enc2[-12:]

assert nonce1 == nonce2

print(f"Ciphertext1: {ct1.hex()}")
print(f"Ciphertext2: {ct2.hex()}")
print(f"Tag1: {tag1.hex()}")
print(f"Tag2: {tag2.hex()}")

assert len(pt1) == len(ct1)
keystream = xor(pt1, ct1)

mod_pt = b"But it's only secure if used correctly!"

mod_ct = xor(keystream[:len(mod_pt)], mod_pt)

def pad16(data):
    """Return padding for the Associated Authenticated Data"""
    #print(data, type(data))
    if len(data) % 16 == 0:
        return bytearray(0)
    else:
        return bytearray(16-(len(data)%16))


def divceil(divident, divisor):
    """Integer division with rounding up"""
    quot, r = divmod(divident, divisor)
    return quot + int(bool(r))

chachanonce = nonce1

tag1_int = int.from_bytes(tag1, 'little')
tag2_int = int.from_bytes(tag2, 'little')

Pr.<x> = PolynomialRing(GF(2^130-5))
x = Pr.gen()

def make_poly(ct):
    data = b""
    mac_data = data + pad16(data)
    mac_data += ct + pad16(ct)
    mac_data += struct.pack('<Q', len(data))
    mac_data += struct.pack('<Q', len(ct))
    f = 0
    for i in range(0, divceil(len(mac_data), 16)):
        n = mac_data[i*16:(i+1)*16] + b'\x01'
        n += (17-len(n)) * b'\x00'
        f = (f + int.from_bytes(n, 'little')) * x
    return f



f1 = make_poly(ct1)
f2 = make_poly(ct2)


print(f"Pol1: {f1}")
print(f"Pol2: {f2}")


res = []

for k in range(-4, 5):
    rhs = tag1_int - tag2_int + 2^128 * k
    #print(rhs, k)
    f = rhs - (f1 - f2)
    for r, _ in f.roots():
        if int(r).bit_length() <= 124:
            s = (tag1_int - int(f1(r))) % 2^128
            res.append((r, s))

    
print(f"Possible result: {res}")

assert len(res) == 1

for r, s in res:
    print(f"using param ({r}, {s})")
    f = make_poly(mod_ct)
    tag = (int(f(r)) + s) % 2^128
    print("computed tag", tag)
    tag = int(tag).to_bytes(16, 'little')
    data = mod_ct + tag + chachanonce
    print(f"Sending: {data.hex()}")
    conn.sendline(data.hex().encode())
    print(conn.recvline())
    print(conn.recvline())

