from pwn import *
from hashlib import *
import random
import os
from Crypto.Util.number import *
with open('shattered-1.pdf','rb') as f:
	s1=f.read()
with open('shattered-2.pdf','rb') as f:
	s2=f.read()
c=connect('34.105.241.228', 1338)
c.recvuntil(b'Solve PoW for ')
tmp=bytes.fromhex(c.recvline().decode()[:-1])
print(tmp)
def solve_for_pow(tmp):

	while True:
		t=os.urandom(5)
		s=sha1(tmp + t).hexdigest()
		if s.endswith('000000'):
			return t.hex()

c.sendline(solve_for_pow(tmp))
c.recvuntil(b'<')
tmp=c.recvline()[:-2].decode()
tmp=tmp.split(', ')
p=int(tmp[0][2:])
q=int(tmp[1][2:])
g=int(tmp[2][2:])
y=int(tmp[3][2:])
h1=bytes_to_long(sha1(bytes.fromhex(s1.hex())).digest())%q
h2=bytes_to_long(sha1(bytes.fromhex(s2.hex())).digest())%q
print(f"p: {p}")
print(f"q: {q}")
print(f"g: {g}")
print(f"y: {y}")
c.recvuntil(b'what would you like me to sign? in hex, please\n')
c.sendline(s1.hex())
tmp=c.recvline()[1:-2].decode()
tmp=tmp.split(', ')
r1=int(tmp[0][2:])
s1=int(tmp[1][2:])
print(f"r1: {r1}")
print(f"s1: {s1}")
c.recvuntil(b'what would you like me to sign? in hex, please\n')
c.sendline(s2.hex())
tmp=c.recvline()[1:-2].decode()
tmp=tmp.split(', ')
r2=int(tmp[0][2:])
s2=int(tmp[1][2:])
print(f"r2: {r2}")
print(f"s2: {s2}")
c.recvline()
c.recvline()
def cal_k(g,p,q,h1,h2,s1,s2,r1,r2):
	tu = s2*pow(r2,-1,q) - h1*pow(r2,-1,q) + h1*pow(r1,-1,q)
	mau=s1*pow(r1,-1,q) - s2*pow(r2,-1,q)
	return (tu*pow(mau,-1,q))%q
def cal_x(k,s,h,r,q):
	return ((k*s-h)*pow(r,-1,q))%q
k=cal_k(g,p,q,h1,h2,s1,s2,r1,r2)
x=cal_x(k,s1,h1,r1,q)

h=bytes_to_long(sha1(b'give flag').digest())
r = pow(g, k, p) % q
s = (pow(k, q - 2, q) * (h + x * r)) % q
c.sendline(str(r))
c.sendline(str(s))
flag=c.recvline()
print(flag)
flag=c.recvline()
print(flag)
