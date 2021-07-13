from pwn import *
from Crypto.Util.number import *
with open('shattered-1.pdf','rb') as f:
	s1=f.read()
with open('shattered-2.pdf','rb') as f:
	s2=f.read()
c=connect('mc.ax',31538)
tmp=c.recvuntil(b'proof of work: ')
proof=c.recvline()[:-1]
ans=subprocess.check_output(proof,shell=True)[:-1]
tmp=c.recvuntil(b'solution: ')
c.sendline(ans)
p=int(c.recvline())
q=int(c.recvline())
g=int(c.recvline())
y=int(c.recvline())
tmp=c.recvuntil(b'what would you like me to sign? in hex, please\n')
print(tmp)
c.sendline(s1.hex())
h1=int(c.recvline())
r1=int(c.recvline())
s1=int(c.recvline())
print(f"p: {p}")
print(f"q: {q}")
print(f"g: {g}")
print(f"y: {y}")
print(f"h1: {h1}")
print(f"r1: {r1}")
print(f"s1: {s1}")
tmp=c.recvuntil(b'what would you like me to sign? in hex, please\n')
print(tmp)
c.sendline(s2.hex())
h2=int(c.recvline())
r2=int(c.recvline())
s2=int(c.recvline())
print(f"h2: {h2}")
print(f"r2: {r2}")
print(f"s2: {s2}")

def cal_k(g,p,q,h1,h2,s1,s2,r1,r2):
	tu = s2*pow(r2,-1,q) - h1*pow(r2,-1,q) + h1*pow(r1,-1,q)
	mau=s1*pow(r1,-1,q) - s2*pow(r2,-1,q)
	return (tu*pow(mau,-1,q))%q
def cal_x(k,s,h,r,q):
	return ((k*s-h)*pow(r,-1,q))%q
k=cal_k(g,p,q,h1,h2,s1,s2,r1,r2)
x=cal_x(k,s1,h1,r1,q)
tmp=c.recvuntil(b"'give flag':")
h=int(c.recvline())
print(h)
r = pow(g, k, p) % q
s = (pow(k, q - 2, q) * (h + x * r)) % q
c.sendline(str(r))
c.sendline(str(s))
flag=c.recvline()
print(flag)
