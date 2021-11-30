from itertools import cycle

def xxor(a, b):
    return [i ^ j for i, j in zip(a, cycle(b))]

FLAG = open('flag.bin', 'rb').read()
f = open('beaches.txt', 'rb').read()

c = int(f[0x636f:0x636f+4]) & 0xff
o = int(f[0x2752298:0x2752298+4]) & 0xff
t = int(f[0x616e:0x616e+4]) & 0xff
h = int(f[0xfdeade:0xfdeade+4]) & 0xff
a = int(f[0x1a185b8:0x1a185b8+4]) & 0xff
n = int(f[0x636f74:0x636f74+4]) & 0xff
_ = int(f[0x6969:0x6969+4]) & 0xff
b = int(f[0xdeadbe:0xdeadbe+4]) & 0xff
r = int(f[0x25a5a58:0x25a5a58+4]) & 0xff
u = int(f[0x686e61:0x686e61+4]) & 0xff
i = int(f[0xbeef:0xbeef+4]) & 0xff
s = int(f[0x746f63:0x746f63+4]) & 0xff
e = int(f[0x10101:0x10101+4]) & 0xff
y = int(f[0x1fffffe:0x1fffffe+4]) & 0xff
key = [c,o,t,h,a,n,_,s,a,y,s,_,y,o,u,_,a,r,e,_,a,_,b,i,t,t,h]

cipher = xor(FLAG, key)

with open('cipher.enc', 'wb') as g:
    g.write(f[:20])
    g.write(bytearray(cipher))
    
