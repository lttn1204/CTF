import json
from sage.combinat import permutation
from Crypto.Util.number import *
n = 25_000
Sn = SymmetricGroup(n)

output = json.load(open('output.json', 'r'))
g = Sn(output['g'])
h = Sn(output['h'])
t1 = Sn(output['t1'])
t2 = Sn(output['t2'])
for k in range(n):
	if t1==g^k:
		break
m=t2*(h^-k)

flag=0
arr=list(Sn.domain())
a=m.domain()
for i in a:
	flag+=arr.index(i)*factorial(len(arr)-1)
	arr.remove(i)
print(long_to_bytes(flag))
