# Gold_digger
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
 - Flow của bài ```Gen seed đầu tiên``` -> ```Gen ra 64 số để encrypt flag``` -> ```wrap() để đối seed``` -> ```Gen ra 64 số cho chúng ta biết```

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
    
![] ( 
