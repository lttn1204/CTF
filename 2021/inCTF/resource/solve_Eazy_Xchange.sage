import pickle
with open('enc.pickle', 'rb') as f:
	x = pickle.load(f)
import os
import hashlib
from Crypto.Cipher import AES
c=bytes.fromhex('9dcc2c462c7cd13d7e37898620c6cdf12c4d7b2f36673f55c0642e1e2128793676d985970f0b5024721afaaf02f2f045')
iv=bytes.fromhex('cbd6c57eac650a687a7c938d90e382aa')


def decrypt(msg, key):
	key = hashlib.sha256(str(key).encode()).digest()[:16]
	cipher = AES.new(key, AES.MODE_CBC, iv)
	return cipher.decrypt(msg)

p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = p - 3
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
EC = EllipticCurve(GF(p), [a, b])
G = EC.gens()[0]
while True:
	k1=os.urandom(4)
	P = sum([i*G for i in k1])
	k2=os.urandom(4)
	SS= sum([i*P for i in k2])
	flag=decrypt(c,SS.xy()[0])
	if b'inctf{' in flag:
		print(flag)
		break
