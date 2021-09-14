##Vì giải này server đóng khi kết thúc, mà hì lại đến 3 bài blackbox nên mình chỉ đưa ra ý tưởng thôi nhé :((

# Forgery

```py
from Crypto.Util.number import getPrime
from random import randint
from math import gcd

with open("flag.txt",'r') as f:
	flag = f.read()

p = getPrime(1024)
g = 3
MASK = 2**1024 - 1

def gen_keys():
	x = randint(1, p-2)
	y = pow(g, x, p)
	return (x, y)

def sign(answer: str, x: int):
	while True:
		m = int(answer, 16) & MASK
		k = randint(2, p-2)
		if gcd(k, p - 1) != 1:
			continue 
		r = pow(g, k, p)
		s = (m-x*r) * pow(k,-1,p-1) % (p-1)
		if s == 0:
			continue
		return (r,s)

def verify(answer: str, r: int, s: int, y: int):
	m = int(answer, 16) & MASK
	if any([x <= 0 or x >= p-1 for x in [m,r,s]]):
		return False
	return pow(g, m, p) == (pow(y, r, p) * pow(r, s, p)) % p

def main():
	x, y = gen_keys()
	print(f"Server's public key (p,g,y): {p} {g} {y}")
	print("Who do you think is the tech wizard: Felicity or Cisco or both? Please answer it with your signnature (r,s)")
	print('Answer: ')
	answer = input()
	print('r: ')
	r = int(input())
	print('s: ')
	s = int(input())
	answer_bytes = bytes.fromhex(answer)

	if b'Felicity' not in answer_bytes and b'Cisco' not in answer_bytes and b'both' not in answer_bytes:
		print("Error: the answer is not valid!")
	elif verify(answer, r, s, y):
		if b'Felicity' in answer_bytes:
			print("I see you are a fan of Arrow!")
		elif b'Cisco' in answer_bytes:
			print("I see you are a fan of Flash!")
		else:
			print("Brown noser!")
		print(flag)
	else:
		print("Error: message does not match given signature")

if __name__ == "__main__":
	main()
```
Nhìn qua source server thì thấy đây là 1 bài [Elgamal Signature](https://en.wikipedia.org/wiki/ElGamal_signature_scheme) 

Đề bài cho ta các tham số public  p,g,y và yêu cầu ta kí 1 message phải có từ ```Felicity``` hoặc ```Cisco``` hoặc ```both```

Thường thì các bài về signature sẽ cho 1 hoặc 1 vài signature của các message để có thể tìm điểm yếu, nhưng bài này thì không :((

Trong Elgamal signature từ ```g```,```p```và private key ```x```, ta sẽ có public key 

![](https://github.com/lttn1204/CTF/blob/main/2021/csawCTF/image/2.png)

Lúc này với message m và 1 số k chọn tùy ý signature sẽ được gen như sau: 

![](https://github.com/lttn1204/CTF/blob/main/2021/csawCTF/image/1.png)

Cặp giá trị r và s là signature của message m 

Vậy để verify signature, server sẻ kiểm tra

![](https://github.com/lttn1204/CTF/blob/main/2021/csawCTF/image/3.png)

Vì m = x\*k + k\*s nên phương tình trên đúng và signature là hợp lệ

Thông thường nếu như không biết được giá trị private key ```x``` thì sẽ rất khó để kí được 1 message.

Sau khi google và tìm hiểu thì mình thấy:
Nếu như ta chọn 1 số ```e``` tùy ý, lúc này không cần biết ```x``` ta có thể tính ```r``` và ```s``` như sau:

![](https://github.com/lttn1204/CTF/blob/main/2021/csawCTF/image/4.png)

r và s này sẽ là 1 cặp signature đúng cho message  ```m = e*s mod(p-1)```   vì khi server  verify signature  sẽ kiểm tra:

![](https://github.com/lttn1204/CTF/blob/main/2021/csawCTF/image/5.png)

Vậy đến đây ta có thẻ sign được message có dạng ```m = e*s mod(p-1)``` nhưng ta không thể control được giả trị này. Vấn đề là làm sao cho message m này phải có 1 trong ba chữ cái nêu ở đầu bài.

Đọc kĩ lại code, mình phát hiện:  ```Lúc server kiểm tra xem có 1 trong ba chữ cái kia ở trong message hay không thì sẽ kiểm tra đúng input của chúng ta, nhưng khi verify signature của nó thì chỉ lấy giá trị m &MASK```

Lợi dụng điểm này mình có thể input message m có chứa ```both``` mà vẫn đảm bảo signature là đúng bằng cách để ```both``` nàm ngoài số bit của MASK

```py
def solve(g,p,y,MARK):
    e = randint(1, p-1)
    r = y*pow(g,e,p) % p
    s = -r % (p - 1)
    m = (e*s) % (p-1)
    m += (bytes_to_long(b'both') << MARK.bit_length())
    return(hex(m),r,s)
 ```
 
 Gửi kết quả và có flag :) 
    
# Gotta Decrypt Them All

1 bài blackbox khi connect vào server yêu cầu chúng ta code 1 chuỗi mã morse rất dài trong 1 khoảng thời gian khá ngắn => chỉ có thể code không thể decode bằng cơm :)

decode morse code xong thì tiếp tục ->  convert asscii to char -> base64 -> được 1 string có dạng ```n=*********** e=3 c=*******```

=> RSA với e và c nhỏ => lấy can bặc 3 của c và cuôi cùng decode root 13.

Làm lại các bước trên 6 lần và có flag.

```py
from pwn import *
import morse_talk as mtalk
from base64 import *
import codecs
from gmpy2 import *
from Crypto.Util.number import *
def to_char(enc):
	enc=bytes(enc)
	enc=b64decode(enc)
	print(enc)
	enc=enc.split(b"\n")
	c=int(enc[2][4:])
	return long_to_bytes(iroot(c,3)[0])
p=connect('crypto.chal.csaw.io', 5001)
for i in range(6):
	tmp=p.recvuntil(b'What does this mean?')
	print(tmp)
	p.recvline()
	enc=p.recvline()[:-3].decode()
	print(enc)
	enc=enc.replace("/"," ")
	enc=mtalk.decode(enc)
	print(enc)
	enc=str(enc)
	result=[]
	i=0
	while i<len(enc):
		if enc[i]!='1':
			result.append(int(enc[i:i+2]))
			i=i+2
		else:
			result.append(int(enc[i:i+3]))
			i=i+3
	print(result)
	s=to_char(result).decode()
	result=codecs.decode(s, 'rot_13')
	print(result)
	p.sendline(result)
	i+=1
flag=p.recvline()
print(flag)
flag=p.recvline()
print(flag)
flag=p.recvline()
print(flag)
flag=p.recvline()
print(flag)
```

# RSA POP QUIZ

Bài này chỉ đơn giản hỏi về các dạng attack quen thuộc của RSA

### Part 1: RSA với e lớn => wiener attack 

### Part 2: RSA với hint là prime prime gì đó mình quên rồi :((. Nghe tới prime mình đoán đề cho 2 prime gần nhau, mà khi 2 prime gần nhau ta có thể dể dàng factor bằng fermat factor

### Part 3: Server cho ta nhâp input và trả về 0 hoặc 1 => RSA LSB oracle attack

### Part 4: Server cho N 1024 bit,e,c và d0 là 512 bit cuối cùng của N => partial key exposure attack 





# ECC POP QUIZ 

Tương tự bài RSA POP QUIZ thì bài này cũng sẽ hỏi về các dạng attack quen thuôc của ECC

### PART 1: Server cho các tham số của đường cong và 2 điểm P1, P2 nhiệm vụ là tìm số x sao cho P1\*x = P2

Kiểm tra thấy order của P1 = order của E => smart attack
```py 
def SmartAttack(P,Q,p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P,y_P = p_times_P.xy()
    x_Q,y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)
```

### PART 2: Đề tiếp tục cho 1 đường cong và 1 điểm P1,P2. Nhưng lần này order của P1 có thể factor ra thành nhiều số nguyên tố nhỏ

Do đó ta có thể tính toán các bài toán logaric rời rạc modulo các số nguyên tố  nhỏ, sau đó dùng CRT để suy ra được g trị x (Pohlig Hellman Attack)

```py
def pohlig_hellman(P1,P2):
	factors, exponents = zip(*factor(E.order()))
	primes = [factors[i] ^ exponents[i] for i in range(len(factors))]
	dlogs = []
	for fac in primes:
		t = int(int(P1.order()) // int(fac))
		dlog = discrete_log(t*P2,t*P1,t*P1.order(),operation="+")
		dlogs += [dlog]
	l = crt(dlogs,primes)
	return l
```
### PART 3: Lần này đề chỉ cho P1, P2 và p không cho 2 giá trị a,b của đường cong

Dù không cho a,b k nhưng ta vẫn có thể dễ dàng tìm ra 2 giá trị này: 

Ta biết đường cong có dạng 

![](https://github.com/lttn1204/CTF/blob/main/2021/csawCTF/image/6.png)

Với việc biết 2 điểm P1(x1,y1) và P2(x2,y2) a và b sẽ được tình bằng cách:

![](https://github.com/lttn1204/CTF/blob/main/2021/csawCTF/image/7.png)

Tìm được 2 giá trị a và b, nhưng khi mình dựng lại đường cong bằng sage thấy

![](https://github.com/lttn1204/CTF/blob/main/2021/csawCTF/image/8.png) 

=> singular curve attack 

``` py
def attack(p,a,b,P1,P2)
	F = GF(p)
	K.<x> = F[]
	f = x^3 + a*x + b
	roots = f.roots()
	if roots[0][1] == 1:
	    beta, alpha = roots[0][0], roots[1][0]
	else:
	    alpha, beta = roots[0][0], roots[1][0]
	slope = (alpha - beta).sqrt()
	u = (P1[1] + slope*(P1[0]-alpha))/(P1[1] - slope*(P1[0]-alpha))
	v = (P2[1] + slope*(P2[0]-alpha))/(P2[1] - slope*(P2[0]-alpha))
	flag = discrete_log(v, u)
	return flag
```
Xong Part này là có được flag

# Thanks for reading and have a nice day !!!!
