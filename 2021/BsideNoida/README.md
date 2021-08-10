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


