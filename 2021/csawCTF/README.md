Vì giải này server đóng khi kết thúc, mà crypto thì lại đến 3 bài blackbox nên mình chỉ đưa ra ý tưởng thôi nhé :((

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

Sau khi google và tìm hiểu thì mình thấy :
Nếu như ta chọn 1 số e tùy ý, lúc này mình sẽ tính r và s như sau:

![](https://github.com/lttn1204/CTF/blob/main/2021/csawCTF/image/4.png)

r và s này sẽ là 1 cặp signature đúng cho message  m = e\*s  vì khi server verify sẽ tính:

![](https://github.com/lttn1204/CTF/blob/main/2021/csawCTF/image/5.png)
