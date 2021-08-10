# baby_crypto

```py 
from functools import reduce
from operator import mul
from secrets import token_bytes
from sys import exit

from Crypto.Util.number import bytes_to_long, getPrime, long_to_bytes


def main():
	a = getPrime(512)
	b = reduce(mul, [getPrime(64) for _ in range(12)])
	flag = open("flag.txt", 'rb').read()
	flag_int = bytes_to_long(flag + token_bytes(20))
	if flag_int > b:
		print("this was not supposed to happen")
		exit()
	print("Try decrypting this =>", pow(flag_int, a, b))
	print("Hint =>", a)
	print("Thanks for helping me test this out,")
	print("Now try to break it")
	for _ in range(2):
		inp = int(input(">>> "))
		if inp % b in [0, 1, b - 1]:
			print("No cheating >:(")
			exit()
		res = pow(flag_int, inp * a, b)
		print(res)
		if res == 1:
			print(flag)


if __name__ == "__main__":
	try:
		main()
	except Exception:
		print("oopsie")
```
Tóm tắc 1 chút:
* Đề gen 1 số nguyên tố a và 1 số b có thể factor thành nhiều các số nguyên tố nhỏ.

 * Ta biết ```flag^a mod b``` và (thật ra là flag+token_bytes nhưng nó không quan trọng lắm) và giá trị a

* Server cho ta 2 lần input, mỗi lần input 1 số ```x``` nào đó, server sẽ trả về ```flag^(a*x)  mod b```

* Nếu ta input 1 số ```x``` nào đó để    ```flag^(a*x)  mod b == 1 ``` thì sẽ có flag 

Dễ thấy mục tiêu của chúng ta là tìm ra ```phi(b)```, mà muốn tìm ra ```phi(b)``` thì phải tìm ra được các số nguyên tố nhỏ của b.

Ta thấy phép tính ```flag^(a*x)  mod b``` tương đương với ```(flag^a)^x mod b```. Vậy giả sử mình gọi ```flag^a mod b``` là ```c``` input số ```2``` và mình được ```c1```.

Lúc này  ```c^2 mod b == c1```  => ```c^2= k*b + c2``` => ```k*b =  c^2 - c1```

Minh factor ```k*b``` tìm lại được các số nguyên tố gen ra b , tính ```Euler_phi(b)``` và gửi lên server để lấy flag. 

### Note:
Thật ra cách của mình khá là sida và factor hơi lâu, để có thể factor nhanh hơn thì có thể làm như sau:
* gửi 2 lên server để nhận lại c1
* gửi 3 lên server để nhận lại c2
* luc này b= gcd(c^2 - c1,c^3 - c2) 

Factor b lúc này sẽ nhanh hơn rất nhìu, vì giá trị lúc này là chính là ```b``` chứ không phải là ```kb``` nữa.
Lúc này dễ dàng tính flag bằng cách ```c ^ inverse(a,phi) mod b```. Lúc làm minh chỉ tập trung vào việc input lần đâu tim được b là quên mất cách này (:sad)


# Xoro
```py
#!/usr/bin/env python3
import os

FLAG = open('flag.txt','rb').read()

def xor(a, b):
    return bytes([i^j for i,j in zip(a,b)])

def pad(text, size):
    return text*(size//len(text)) + text[:size%len(text)]

def encrypt(data, key):
    keystream = pad(key, len(data))
    encrypted = xor(keystream, data)
    return encrypted.hex()


if __name__ == "__main__":
    print("\n===== WELCOME TO OUR ENCRYPTION SERVICE =====\n")
    try:
        key = os.urandom(32)
        pt = input('[plaintext (hex)]>  ').strip()
        ct = encrypt(bytes.fromhex(pt) + FLAG, key)
        print("[ciphertext (hex)]>", ct)
        print("See ya ;)")
    except Exception as e:
        print(":( Oops!", e)
        print("Terminating Session!")
```
Phân tích 1 chút: 
* Mỗi lần connect server sẽ gen ra 1 key, cho phép nhập input và encrypt bằng cách ```(input+flag) xor key```
* Key có 32 bytes
* hàm pad đơn giản là lăp lại chuỗi cho đến khi đủ độ dài cần thiết
* Nhập thử 1 kí tự để check thì thấy len(flag)=39

Lúc này minh sẽ lợi dụng vào hàm pad để có thể leak được từng kí tự của flag.

Vì key chỉ có 32 kí tự nên dù input bao nhìu thì chắc chắn key sẽ pad, lúc này key sẽ được lặp lại. Vậy thì kí tự thứ 1 và kí tự thứ 33 sẽ được xor chung 1 key. 

Vậy nếu ta input 32 kí tự thì kí tự đầu tiên của flag sẽ được xor cùng với kí tự đầu tiên của chúng ta.

Mà lúc này ```input[0] xor key[0] = a ```; ```flag[0] xor key[0] = b``` => ```flag[0]= a xor b xor input[0]```

Ta chỉ việc đơn giản lấy kí tự đầu tiên xor với kí tự thú 32 và xor với input đầu tiên la tìm được giá trị đầu tiên của flag.

Tiếp theo cứ giảm input xuống 31 thì sẽ tìm được kí tự thứ 2 .......

Dễ dàng tim lại 32 kí tự đầu của flag, mà có 32 kí tự của flag thì đồng nghĩa với việc có luôn key, 7 kí tự còn lại của flag cũng dễ dàng tìm. 

[solution](https://github.com/lttn1204/CTF/blob/main/2021/BsideNoida/resource/solve_xor.py)  của mình 


# MACAW
```py 
#!/usr/bin/env python3
from topsecrets import iv, key, secret_msg, secret_tag, FLAG
from Crypto.Cipher import AES

iv = bytes.fromhex(iv)

menu = """
/===== MENU =====\\
|                |
|  [M] MAC Gen   |
|  [A] AUTH      |
|                |
\================/
"""

def MAC(data):    
    assert len(data) % 16 == 0, "Invalid Input"
    assert data != secret_msg, "Not Allowed!!!"
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    tag = cipher.encrypt(data)[-16:]
    return tag.hex()

def AUTH(tag):
    if tag == secret_tag:
        print("[-] Successfully Verified!\n[-] Details:", FLAG)
    else:
        print("[-] Verification Flaied !!!")

if __name__ == "__main__":
    print(secret_msg)
    try:
        for _ in range(3):
            print(menu)
            ch = input("[?] Choice: ").strip().upper()
            if ch == 'M':
                data = input("[+] Enter plaintext(hex): ").strip()
                tag = MAC(bytes.fromhex(data))
                print("[-] Generated tag:", tag)
                print("[-] iv:", iv.hex())
            elif ch == 'A':
                tag = input("[+] Enter your tag to verify: ").strip()
                AUTH(tag)
            else:
                print("[!] Invalid Choice")
                exit()
    except Exception as e:
        print(":( Oops!", e)
        print("Terminating Session!")
```
Tóm tắc: 
* Đề cung cấp 1 server encrypt AES CBC và 1 secret_message
* Ta không được input secret_message để server encrypt
* Nếu ta có được encrypt của secret_message thì có flag
* Ta chỉ được input cho server encrypt 2 lần và 1 lần để verify
* Key và IV được import từ 1 file khác -> key và IV không đổi -> mỗi lần connect đêu dùng chung key và IV -> không bị giới hạn bởi 2 lần input.

Encrypt AES-CBC được thực hiện như sau :

![](https://github.com/lttn1204/CTF/blob/main/2021/BsideNoida/image/CBC.png)

Trong CBC thì mỗi block trước khi encrypt sẽ được ```xor``` với ciphertext block trước đó, tiêng block đầu tiên thì ```xor``` với IV

TA thấy ```secret_message``` là ```Welcome to BSidesNoida!! Follow us on Twitter...``` có 48 bytes vừa khít với hình luôn :v 

Cách làm của mình là ban đầu sẽ input 2 block đầu của ```secret_message``` lúc này mình nhận về 1 giá trị gọi là ```enc```

Vậy thì giả sử chung ta đang encrypt thằng ```secret_message``` thì thằng ```enc``` là kết quả ở chổ mình đánh dấu X màu đỏ (trên hình ý)

Vậy nếu tiếp theo quá trinh encrypt ```secret_message``` thì block 3 sẽ được xor với ```enc``` rồi encrypt.

Quay lại, bây giờ nếu ta gửi block 3 lên server thì sever sẽ thực hiện: encrypt(block3 xor IV).

Vậy để control được thành encrypt(block3 xor enc) thì đơn giản ta chỉ cần lấy block3 xor với enc rồi xor lại tiếp với IV.

Lúc này server sẽ thực hiện encrypt(block3 xor enc xor IV xor IV) = encrypt(block3 xor enc). Giá trị server trả về lúc này chính là encrypt của ```secret_msg``` cần tìm. 

Nếu làm theo cách này thì chỉ cần 2 lần input là đủ và ở mỗi lần connect đổi IV, key, s thì vẫn có thể giải được.

# MACAW_Revenge
```py 
#!/usr/bin/env python3
from Crypto.Cipher import AES
import os

with open('flag.txt') as f:
    FLAG = f.read()


menu = """
/===== MENU =====\\
|                |
|  [M] MAC Gen   |
|  [A] AUTH      |
|                |
\================/
"""

def MAC(data, check=False):    
    assert len(data) % 16 == 0, "Invalid Input"
    
    if check:
        assert data != secret_msg, "Not Allowed!!!"
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    tag = cipher.encrypt(data)[-16:]
    return tag.hex()

def AUTH(tag):
    if tag == secret_tag:
        print("[-] Successfully Verified!\n[-] Details:", FLAG)
    else:
        print("[-] Verification Flaied !!!")

if __name__ == "__main__":
    iv = os.urandom(16)
    key = os.urandom(16)
    secret_msg = os.urandom(48)
    secret_tag = MAC(secret_msg)

    print(f"[+] Forbidden msg: {secret_msg.hex()}")
    try:
        for _ in range(3):
            print(menu)
            ch = input("[?] Choice: ").strip().upper()
            if ch == 'M':
                data = input("[+] Enter plaintext(hex): ").strip()
                tag = MAC(bytes.fromhex(data), check=True)
                print("[-] Generated tag:", tag)
                print("[-] iv:", iv.hex())
            elif ch == 'A':
                tag = input("[+] Enter your tag to verify: ").strip()
                AUTH(tag)
            else:
                print("[!] Invalid Choice")
                exit()
    except Exception as e:
        print(":( Oops!", e)
        print("Terminating Session!")
```
Bài này y như bài MACAW trước, chỉ đơn giản là mỗi lần coonect thì key,iv và secret_msg đều đổi.

Như đã phân tích thì cách làm ở trên cũng work với bài này luôn. Nên vừa ra chall mình solve liền :hihi

![](https://github.com/lttn1204/CTF/blob/main/2021/BsideNoida/image/1.jpg)

![](https://github.com/lttn1204/CTF/blob/main/2021/BsideNoida/image/2.jpg)

![](https://github.com/lttn1204/CTF/blob/main/2021/BsideNoida/image/3.jpg)

Kỉ niệm lần đầu được organizer hỏi thăm :hihi

Dù bài này không có gì khó nhưng cũng là 1 kỉ niệm vui với mình.(Vui thiệt luôn á :joy: ) 


# kotf_return
```py
from hashlib import sha1
from random import *
from sys import exit
from os import urandom
from Crypto.PublicKey import DSA
from Crypto.Util.number import *

rot = randint(2, 2**160 - 1)
chop = getPrime(159)


def message_hash(x):
	return bytes_to_long(sha1(x).digest())


def nonce(s, padding, i, q):
	return (pow(message_hash(s), rot, chop) + padding + i)%q


def verify(r, s, m):
	if not (0 < r and r < q and 0 < s and s < q):
		return False
	w = pow(s, q - 2, q)
	u1 = (message_hash(m) * w) % q
	u2 = (r * w) % q
	v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
	return v == r

def pow_solve():
	pow_nonce = urandom(4)
	print(f"Solve PoW for {pow_nonce.hex()}")
	inp = bytes.fromhex(input())
	if sha1(pow_nonce + inp).hexdigest().endswith('000000'):
		print("Correct PoW. Continue")
		return True
	print("Incorrect PoW. Abort")
	return False


try:
	if not pow_solve():
		exit()
	L, N = 1024, 160
	dsakey = DSA.generate(1024)
	p = dsakey.p
	q = dsakey.q
	h = randint(2, p - 2)

	# sanity check
	g = pow(h, (p - 1) // q, p)
	if g == 1:
		print("oopsie")
		exit(1)

	x = randint(1, q - 1)
	y = pow(g, x, p)

	print(f"<p={p}, q={q}, g={g}, y={y}>")

	pad = randint(1, 2**160)
	signed = []
	for i in range(2):
		print("what would you like me to sign? in hex, please")
		m = bytes.fromhex(input())
		if m == b'give flag' or m == b'give me all your money':
			print("haha nice try...")
			exit()
		if m in signed:
			print("i already signed that!")
			exit()
		signed.append(m)
		# nonce generation remains the same
		k = nonce(m, pad, i, q)
		if k < 1:
			exit()
		r = pow(g, k, p) % q
		if r == 0:
			exit()
		s = (pow(k, q - 2, q) * (message_hash(m) + x * r)) % q
		if s == 0:
			exit()
		# No hash leak for you this time
		print(f"<r={r}, s={s}>")

	print("ok im done for now. You visit the flag keeper...")
	print("for flag, you must bring me signed message for 'give flag'")

	r1 = int(input())
	s1 = int(input())
	if verify(r1, s1, b"give flag"):
		print(open("flag.txt").read())
	else:
		print("Never gonna give you up")
except:
	print("Never gonna let you down")
```
Bài này giống đến hơn 90% bài ``keeper of the flag`` ở ```redpwn CTF```. Chỉ khác ở việc ban đầu phải vượt qua ```pow_solve```.
Ở bước này chỉ cần brute force là có thể vượt qua được:
```py
def solve_for_pow(tmp):
	while True:
		t=os.urandom(5)
		s=sha1(tmp + t).hexdigest()
		if s.endswith('000000'):
			return t.hex()
```
Còn các bước còn lại không khác gì

Ý tưởng chính để giải:
* Server có ta input message để sign DSA
* Nếu như ta có thể nhập 1 collison sha1 thì k ở lần nhập sau sẽ bằng k trước đó + 1
* Lợi dụng điểm yếu này để tìm lại x và kí được b'give flag'

Mình đã có write up  và phân tích bài ```keeper of the flag``` ở [đây](https://github.com/lttn1204/CTF/tree/main/2021/redpwnCTF/Kepper_of_the_flag) mọi người có thể đọc để hiêu thêm nhé

# Thanks for reading and have a nice day!!!
