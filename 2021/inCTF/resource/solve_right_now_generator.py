from Crypto.Cipher import AES
import gmpy2
import hashlib
from Crypto.Util.number import *
import  pickle
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

with open('enc.pickle','rb') as f:
	data=pickle.load(f)
iv=bytes.fromhex(data['iv'])
encrypted=bytes.fromhex(data['cip'])
tmp=data['leak']
leak=[]
for i in range(0,len(tmp),16):
	leak.append(int(tmp[i:i+16],16))
#print(enc)
pad = 0xDEADC0DE
sze = 64
n = int(gmpy2.next_prime(2**sze))
def find_seed(leak):
	seed=[]
	for i in range(0,len(leak),2):
		a=(leak[i]+leak[i+1])%n
		b=(leak[i+1]+a)%n
		seed.append(a)
		seed.append(b)
	return seed
seed=find_seed(leak)
#print(seed)
old_seed=[1]*64
for i in range(32,64):
	temp=inverse(seed[i-32],n)
	temp=(temp*seed[i])%n
	old_seed[i]=temp^pad

for i in range(32):
	tmp=inverse(old_seed[i+32],n)
	tmp=(tmp*seed[i])%n
	old_seed[i]=tmp^pad%n
#print(old_seed)
obj=RNG(0,old_seed)
key=''.join([format(obj.next(), '016x') for i in range(64)])
key = hashlib.sha256(bytes.fromhex(key)).digest()[:16]
cipher=AES.new(key,AES.MODE_CBC,iv)
flag=cipher.decrypt(encrypted)
print(flag)
