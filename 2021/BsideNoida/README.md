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
