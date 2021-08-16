#!/usr/bin/env python3

import random, hashlib, os, gmpy2, pickle
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

#FLAG = open('flag.txt', 'rb').read()

class RNG():
	pad = 0xDEADC0DE
	sze = 64
	mod = int(gmpy2.next_prime(2**sze))
	def __init__(self, seed_val, seed=None):
		if seed == None:
			assert seed_val.bit_length() == 64*2, "Seed is not 128 bits!"
			self.seed = self.gen_seed(seed_val)
			self.wrap()
		else:
			self.seed = seed
			self.ctr = 0
	def gen_seed(self, val):
		ret = [val % self.mod]
		val >>= self.sze
		for i in range(self.sze - 1):
			val = pow(i ^ ret[i] ^ self.pad, 3, self.mod)
			ret.append(val % self.mod)
			val >>= self.sze
		return ret
	def wrap(self, pr=True):
		hsze = self.sze//2
		for i in range(self.sze):
			r1 = self.seed[i]
			r2 = self.seed[(i+hsze)%self.sze]
			self.seed[i] = ((r1^self.pad)*r2)%self.mod
		self.ctr = 0
	def next(self):
		a, b, c, d = (self.seed[self.ctr^i] for i in range(4))
		mod = self.mod
		k = 1 if self.ctr%2 else 2
		a, b, c, d = (k*a-b)%mod, (b-c)%mod, (c-d)%mod, (d-a)%mod
		self.ctr += 1
		if self.ctr==64:
			self.wrap(pr=False)
		return a

def encrypt(key: bytes, pt: bytes) -> bytes:
	key = hashlib.sha256(key).digest()[:16]
	cipher = AES.new(key, AES.MODE_CBC, os.urandom(16))
	return {'cip': cipher.encrypt(pad(pt, 16)).hex(), 'iv': cipher.IV.hex()}

def main():
	obj = RNG(random.getrandbits(128))
	out1 = ''.join([format(obj.next(), '016x') for i in range(64)])
	out2 = ''.join([format(obj.next(), '016x') for i in range(64)])
	cip = encrypt(bytes.fromhex(out1), FLAG)
	cip['leak'] = out2
	return cip

if __name__ == '__main__':
	cip = main()
	pickle.dump(cip, open('enc.pickle', 'wb'))
	
#{'cip': '71d39d37d3c03e08b82d81ae3b4be658e2dbdaee6a73d73a3e88271f423db30f0422d4fb9475ceef281a746afa86eaee', 'iv': 'cbf411655acfd7f670968ccf44d74e05', 'leak': '3aeba43302ab9ad0df898103fc0223be23f5ec10f62ad48744c2ec06bc4ac9b2290aff5f5d17fc2ff2a1115e657ddced0f12238ca12b076bf85fed0ce621202d159c014907e39ba7373ada78a4dea3a76bfb9ff09a8f10705cd95a47edd743fde25f32ab545bf98bba1344bed511b0c095ddede11b4a35bc02acb34d3aef46c56bfc9b668c82c0d3da76307dd87016e1a7df478cdefb98d4fe991088f478f24390fac3d4f0d0673d2801f37df421ab17cb72af64a8b21ebf9d73c3ef35a8bd5fe98c62a910ef8b859b86a58bf670fe544266bc37a36d3828e7397bac0b817f41522e76a68661b3e9952ed3d2eb7846b2f9cd2c1cc44eda2ac536eb826ce922afaa4c7d61ff3db9023cf2fff8fb34791954fbb1541f043fe26e92fb79f119fbe175bd1b551dd1225275a457580bef4301505f474060f39caad6d3172f17a9a21f68e66b59a13e817b0201dbdbcc1e6c1d80ab2e8d38f7f0a62d0bb3577da845643273b1743f5aac064422bdbd85358f6da726f9114c5553432d4f4e2f43f997975add7ea3b6a56b689ff84f7635815879e28d8c7421b979449f5bccb29cce745862610af8c99379c60e1205d5e1eda9d2f5243d4da4325ac142bd196d1777bd2d4f61eb355b7fca3e16295d05e8a21e75f010272ce159afb49fa3d4b97bd242304e34599f7bc8edf5b4430bb42b12437b7c27583d303043311afd56fae70a7d6b'}
