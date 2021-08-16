# Gold_digger
## Challenge
```py
import random
from Crypto.Util.number import *
from gmpy2 import *

flag=open("flag","rb").read()

def encrypt(msg, N,x):
    msg, ciphertexts = bin(bytes_to_long(msg))[2:], []
    for i in msg:
        while True:
            r = random.randint(1, N)
            if gcd(r, N) == 1:
                bin_r = bin(r)[2:]
                c = (pow(x, int(bin_r + i, 2), N) * r ** 2) % N
                ciphertexts.append(c)
                break
    return ciphertexts

N = 76412591878589062218268295214588155113848214591159651706606899098148826991765244918845852654692521227796262805383954625826786269714537214851151966113019

x = 72734035256658283650328188108558881627733900313945552572062845397682235996608686482192322284661734065398540319882182671287066089407681557887237904496283

flag = (encrypt(flag,N,x))

open("handout.txt","w").write("ct:"+str(flag)+"\n\nN:"+str(N)+"\n\nx:"+str(x))
```
Đề cho ta x,N và 1 mảng c rất dài 

Đọc code thì thấy đề encrypt theo mỗi giá trị binary của flag 

Nếu tại bin(flag) =='0' thì : 

![](https://github.com/lttn1204/CTF/blob/main/2021/inCTF/image/ct1.png)

Còn nếu tại bin(flag)=='1':

![](https://github.com/lttn1204/CTF/blob/main/2021/inCTF/image/ct2.png)

Dễ thấy nếu ```bin(flag)[i] =='0'``` thì sẽ tồn tại căn bậc 2 modulo N của c[i], Ngược lại nếu ```bin(flag)[i] =='1'``` thì sẽ không tồn tại căn bậc 2 modulo N của c[i]

Dựa vào điểm này mình sẽ dùng ```jacobi symbol``` để kiểm tra xem từng vị trí của mảng có tồn tại căn bậc  2 modulo N hay không, từ đó có thể tìm lại lần lượt các bit của flag.

đây là [solution](https://github.com/lttn1204/CTF/blob/main/2021/inCTF/resource/solve_gold_digger.py) của mình 

# Right_Now_Generator

## Challenge
```py
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
	
 ```
 Tóm tắc 1 chút:
 - Đề define 1 class RNG và gen ra 128 số. Dùng 64 số đầu làm key để encrypt AES-CBC flag , 64 số còn lại đề cho ta biết
 - Seed là 1 mảng 64 số, với 1 seed thì RNG chỉ gen ra được 64 số qua hàm ```next()``` và sau đó seed sẽ đổi seed khác thông qua hàm ```wrap()```
 - Flow của RNG ```Gen seed đầu tiên``` -> ```Gen ra 64 số để encrypt flag``` -> ```wrap() để đối seed``` -> ```Gen ra 64 số cho chúng ta biết```

Quan sát hàm next:
```py
def next(self):
	a, b, c, d = (self.seed[self.ctr^i] for i in range(4))
	mod = self.mod
	k = 1 if self.ctr%2 else 2
	a, b, c, d = (k*a-b)%mod, (b-c)%mod, (c-d)%mod, (d-a)%mod
	self.ctr += 1
	if self.ctr==64:
		self.wrap(pr=False)
	return a
 ```
 
 Giã sử từ 1 seed ta RNG gen ra 64 số (tạm gọi là ```leak```),  ta thấy với mỗi cặp seed[i] và seed[i+1] (i chẵn) thì:
 
 ![](https://github.com/lttn1204/CTF/blob/main/2021/inCTF/image/ct2.3.png)
    
Biến đổi 1 chút thì ta được:

![](https://github.com/lttn1204/CTF/blob/main/2021/inCTF/image/ct2.2.png)
    
Vậy tù 64 số mà đề cho ta dẽ tìm lại được seed của 64 số ấy. Việc còn lại là phải tìm được seed của 64 số dùng để encrypt flag

Tiếp theo ta quan sát hàm swap():
```py
def wrap(self, pr=True):
	hsze = self.sze//2
	for i in range(self.sze):
		r1 = self.seed[i]
		r2 = self.seed[(i+hsze)%self.sze]
		self.seed[i] = ((r1^self.pad)*r2)%self.mod
	self.ctr = 0
```
Hàm này sẽ biến đổi từ 1 seed thành seed mới , vậy nếu làm ngược lại được hàm này thì từ seed ta mới tìm ra ở trên, ta có thể tìm lại seed trước của nó (mình tạm gọi ```old_seed```)

Ta thấy hàm wrap() tính seed[i]  bằng cách lấy ```(seed[i] xor pad)* seed[(i+32)%64]```

Nhưng hàm này lấy đầu vào của seed và cập nhật thẳng giá trị mới tìm được lên seed luôn.

Vậy thì khi tính toán từ seed[0] -> seed[31] thì các gía trị cần để tính toán là 2 giá trị seed[i] và seed[(32+i)%64] của seed cũ(chưa biết 2 giá trị này).

Nhưng khi tính toán từ seed[32] trở đi thì giá trị cần để tính toán là 2 giá trị seed[i] và seed[(32+i)%64] lúc này giá trị  seed[(32+i)%64] ta đã biết.

Vậy thì lúc này từ seed ban đầu ta có thể dễ dàng tìm lại old_seed[32:64] qua công thức : ```old_seed[i] = (seed[i] * inverse(seed[(32+i)%64])) ^ pad```

và cũng từ đây ta có thể tìm lại được toán bộ old_seed: ```old_seed[i] = (seed[i] * inverse(old_seed[(32+i)%64])) ^ pad```

Có old_seed, bỏ vào RNG để gen ra key rồi decrypt là có được flag.

[Solution](https://github.com/lttn1204/CTF/blob/main/2021/inCTF/resource/solve_right_now_generator.py) của mình 


# Lost_Baggage
## Challenge

```py
#!/usr/bin/python3

from random import getrandbits as rand
from gmpy2 import next_prime, invert
import pickle

FLAG = open('flag.txt', 'rb').read()
BUF = 16

def encrypt(msg, key):
	msg = format(int(msg.hex(), 16), f'0{len(msg)*8}b')[::-1]
	assert len(msg) == len(key)
	return sum([k if m=='1' else 0 for m, k in zip(msg, key)])

def decrypt(ct, pv):
	b, r, q = pv
	ct = (invert(r, q)*ct)%q
	msg = ''
	for i in b[::-1]:
		if ct >= i:
			msg += '1'
			ct -= i
		else:
			msg += '0'
	return bytes.fromhex(hex(int(msg, 2))[2:])

def gen_inc_list(size, tmp=5):
	b = [next_prime(tmp+rand(BUF))]
	while len(b)!=size:
		val = rand(BUF)
		while tmp<sum(b)+val:
			tmp = next_prime(tmp<<1)
		b += [tmp]
	return list(map(int, b))

def gen_key(size):
	b = gen_inc_list(size)
	q = b[-1]
	for i in range(rand(BUF//2)):Đọc
		q = int(next_prime(q<<1))
	r = b[-1]+rand(BUF<<3)
	pb = [(r*i)%q for i in b]
	return (b, r, q), pb

if __name__ == '__main__':
    pvkey, pbkey = gen_key(len(FLAG) * 8)
    cip = encrypt(FLAG, pbkey)
    assert FLAG == decrypt(cip, pvkey)
    pickle.dump({'cip': cip, 'pbkey': pbkey}, open('enc.pickle', 'wb'))
```
Đọc code thì thấy đây là 1 bài [knapsack cryptosytem](https://en.wikipedia.org/wiki/Merkle%E2%80%93Hellman_knapsack_cryptosystem).

Đầu tiên thì mình nghĩ đến dùng lattice để giải bài này (Mình đọc tài liệu thấy như vậy chứ cũng chưa hiểu được kĩ thuật này :))  )

Sau 1 hồi mò hết các writeup và làm theo vẫn không ra :(  và mình cũng k hiểu tại sao :( thì nhìn lại thằng pubkey thấy nó là 1 mảng supper increasing ( phần tử thứ i lớn hơn tổng tất cả các phần tử trước đó ) 

Vậy thì ta chỉ việc đơn giản decrypt với việc coi nó như 1 thằng private key là được

Mình thử và ra flag :)) 

script mình để ở [đây](https://github.com/lttn1204/CTF/blob/main/2021/inCTF/resource/solve_lost_baggage.py)


# Eazy_Xchange
## Challenge

```py
import os, hashlib, pickle
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
key = os.urandom(4)
FLAG = open('flag.txt', 'rb').read()
p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = p - 3
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

def gen_key(G, pvkey):
	G = sum([i*G for i in pvkey])
	return G

def encrypt(msg, key):
	key = hashlib.sha256(str(key).encode()).digest()[:16]
	cipher = AES.new(key, AES.MODE_CBC, os.urandom(16))
	return {'cip': cipher.encrypt(pad(msg, 16)).hex(), 'iv': cipher.IV.hex()}

def gen_bob_key(EC, G):
	bkey = os.urandom(4)
	B = gen_key(G, bkey)
	return B, bkey

def main():
	EC = EllipticCurve(GF(p), [a, b])
	G = EC.gens()[0]
	Bx = int(input("Enter Bob X value: "))
	By = int(input("Enter Bob Y value: "))
	B = EC(Bx, By)
	P = gen_key(G, key)
	SS = gen_key(B, key)
	cip = encrypt(FLAG, SS.xy()[0])
	cip['G'] = str(G)
	return cip

if __name__ == '__main__':
	cip = main()
	pickle.dump(cip, open('enc.pickle', 'wb'))
````
Tóm tặc 1 chút:
- Đề cho ta 1 Elliptic Curve với các tham số a,b trên GF(p) và điểm G
- Đây là bài trao đổi khóa khá lạ vì chỉ cho ta biết duy nhât 1 điểm 
- Mỗi secret key gồm 4 bytes

Với việc dữ kiện ít như vậy thì mình nghĩ sẽ có vấn đề ở hàm gen_key(), mình check thử:
 
 ![](https://github.com/lttn1204/CTF/blob/main/2021/inCTF/image/check.png)
 
Mình nhân  G với 100000 nhưng chỉ có hơn 900 điểm mới được sinh ra (tỉ lệ chưa tới 1%), vậy thì sẽ có rất nhiều key cùng tạo ra 1 điểm 

=> Ta có thể brute force cả 2 key để tìm lại điểm SS để decrypt flag

![](https://github.com/lttn1204/CTF/blob/main/2021/inCTF/image/solve.png)

Mình brute force khá lâu, chắc nhân phẩm dạo này hơi kém :((

# Thanks For Reading And Have A Nice Day !!!


