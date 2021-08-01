# Challenge
```py
#!/usr/bin/env sage

from sage.all import *
import string, base64, math
from flag import flag

ALPHABET = string.printable[:62] + '\\='

F = list(GF(64))

def keygen(l):
	key = [F[randint(1, 63)] for _ in range(l)] 
	key = math.prod(key) # Optimization the key length :D
	return key

def maptofarm(c):
	assert c in ALPHABET
	return F[ALPHABET.index(c)]

def encrypt(msg, key):
	m64 = base64.b64encode(msg)
	enc, pkey = '', key**5 + key**3 + key**2 + 1
	for m in m64:
		enc += ALPHABET[F.index(pkey * maptofarm(chr(m)))]
	return enc

# KEEP IT SECRET 
key = keygen(14) # I think 64**14 > 2**64 is not brute-forcible :P

enc = encrypt(flag, key)
print(f'enc = {enc}')
```

Để tạo key thì đầu tiên chương trình lấy ngẫu nhiên l phần tư trong ```GF(64)``` và nhân tất cả chúng lại với nhau được 1 key, cuồi cùng lấy key = key^5 +key^3 +key^2 +1

Do tính chất khép kín nên khi trải qua nhìu bước làm phía trên thì key cũng sẽ chỉ  nằm trong GF(64) -> Vậy chỉ chó 64 key tất cả có thẻ gen ra nên ta có thể brute force để tìm 

Đã có key thì ta hoàn toàn có thể đảo ngược lại code để tìm flag.

Hoặc nếu lười như mình thì có thể brute force tiếp để tìm ```m``` sao cho thỏa  ```enc = ALPHABET[F.index(pkey * maptofarm(chr(m)))]``` với mỗi vị trí của ```enc``` và ```m```

[Solution](https://github.com/lttn1204/CTF/blob/main/2021/CryptoCTF/farm/solve.sage) của mình 
