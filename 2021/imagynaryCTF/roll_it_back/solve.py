from itertools import *
from gmpy2 import *
from Crypto.Util.number import *
def x(a,b):
    return bytes(islice((x^y for x,y in zip(cycle(a), cycle(b))), max(*map(len, [a, b]))))
def t(x):
    return sum((((x & 28) >> 4) & 1) << i for i, x in enumerate(x))
T = t(x(b"jctf{not_the_flag}", b"*-*")) | 1
def test(x,last_bit):
	return popcount(int(x+last_bit,2)&T)&1	
flag_enc=2535320453775772016257932121117911974157173123778528757795027065121941155726429313911545470529920091870489045401698656195217643
l=420
enc=bin(flag_enc)[2:]
enc=enc.rjust(l,'0')
print(enc)
for _ in range(421337):
	for i in ['0','1']:
		if str(test(enc,i))==enc[0]:
			enc+=i
			enc=enc[1:]
			break
			
print(long_to_bytes(int(enc,2))[::-1])

	
