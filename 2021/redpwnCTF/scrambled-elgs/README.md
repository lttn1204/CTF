# Challengeg
Đề cho ta 1 file generate.sage và 1 file [output.json](https://github.com/lttn1204/CTF/blob/main/2021/redpwnCTF/scrambled-elgs/output.json)
```py
#!/usr/bin/env sage
import secrets
import json
from Crypto.Util.number import bytes_to_long, long_to_bytes
from sage.combinat import permutation

n = 25_000
Sn = SymmetricGroup(n)

def pad(M):
    padding = long_to_bytes(secrets.randbelow(factorial(n)))
    padded = padding[:-len(M)] + M
    return bytes_to_long(padded)

#Prepare the flag
with open('flag.txt','r') as flag:
    M = flag.read().strip().encode()
m = Sn(permutation.from_rank(n,pad(M)))

#Scramble the elgs
g = Sn.random_element()
a = secrets.randbelow(int(g.order()))
h = g^a
pub = (g, h)

#Encrypt using scrambled elgs
g, h = pub
k = secrets.randbelow(n)
t1 = g^k
t2 = m*h^k
ct = (t1,t2)

#Provide public key and ciphertext
with open('output.json','w') as f:
	json.dump({'g':str(g),'h':str(h),'t1':str(t1),'t2':str(t2)}, f)
```
Đề khởi tạo SymmetricGroup với n = 25000 cùng với m là element có rank là pad(flag), và cho ta g, h ,t1 ,t2
Quan sát đoạn 
```
k = secrets.randbelow(n)
t1 = g^k
t2 = m*h^k
```
Vì range của k khá bé nên mình brute force để tìm k thõa mãn ```t1 = g^k``` từ đó tim lại m bằng cách lấy t1\*h^-k
```py 
for k in range(n):
	if t1==g^k:
		break
m=t2*(h^-k)
```

