# Challenge
```p
#!/usr/bin/env python3

from hashlib import md5, sha1
import sys
from secret import salt, pepper
from flag import flag

assert len(salt) == len(pepper)	== 19
assert md5(salt).hexdigest()	== '5f72c4360a2287bc269e0ccba6fc24ba'
assert sha1(pepper).hexdigest()	== '3e0d000a4b0bd712999d730bc331f400221008e0'

def auth_check(salt, pepper, username, password, h):
	return sha1(pepper + password + md5(salt + username).hexdigest().encode('utf-8')).hexdigest() == h

def die(*args):
	pr(*args)
	quit()

def pr(*args):
	s = " ".join(map(str, args))
	sys.stdout.write(s + "\n")
	sys.stdout.flush()

def sc():
	return sys.stdin.readline().strip()

def main():
	border = "+"
	pr(border*72)
	pr(border, "  welcome to hash killers battle, your mission is to login into the ", border)
	pr(border, "  ultra secure authentication server with provided information!!    ", border)
	pr(border*72)

	USERNAME = b'n3T4Dm1n'
	PASSWORD = b'P4s5W0rd'

	while True:
		pr("| Options: \n|\t[L]ogin to server \n|\t[Q]uit")
		ans = sc().lower()
		if ans == 'l':
			pr('| send your username, password as hex string separated with comma: ')
			inp = sc()
			try:
				inp_username, inp_password = [bytes.fromhex(s) for s in inp.split(',')]
			except:
				die('| your input is not valid, bye!!')
			pr('| send your authentication hash: ')
			inp_hash = sc()
			if USERNAME in inp_username and PASSWORD in inp_password:
				if auth_check(salt, pepper, inp_username, inp_password, inp_hash):
					die(f'| Congrats, you are master in hash killing, and it is the flag: {flag}')
				else:
					die('| your credential is not valid, Bye!!!')
			else:
				die('| Kidding me?! Bye!!!')
		elif ans == 'q':
			die("Quitting ...")
		else:
			die("Bye ...")

if __name__ == '__main__':
	main()
```
Nhìn qua thì dễ thấy đây là 1 bài ```hash length extension attack``` với cả ```sha1``` và ```md5```

Sơ qua chương trình trình ta biết được ```md5(salt)``` và ```sha1(pepper)``` để get flag thì ta phải tìm được 

```sha1(pepper + password + md5(salt + username)```

với điều kiện là password phải có ```P4s5W0rd``` và username phải có ```n3T4Dm1n```

Ở bài này mình sẽ sử dung ```hash extender``` để attack 

Đầu tiên phải attack được md5 đẻ tìm md5 hash của ```salt + username```

![](https://github.com/lttn1204/CTF/blob/main/2021/CryptoCTF/salt_pepper/md5.png)

md5(salt+ new string) = 95623660d3d04c7680a52679e35f041c
Vậy user name ta cần gửi là new string

Ta tiếp tục attack đến sha1

Vì công thức ```auth_check``` của server là sha1(pepper + password + md5(salt + username) nên phần append ta phải nhập P4s5W0rd + md5 vừa tìm được ở trên 

![](https://github.com/lttn1204/CTF/blob/main/2021/CryptoCTF/salt_pepper/sha1.png)

Vay ta thấy sha1(pepper+ newstring)=83875efbe020ced3e2c5ecc908edc98481eba47f và đây cũng sẽ là giá trị hash mà ta gui lên server.

Vậy password ta cần gửi là newstring - b'95623660d3d04c7680a52679e35f041c'.hex()

Gửi lên server và lấy flag :d

![](https://github.com/lttn1204/CTF/blob/main/2021/CryptoCTF/salt_pepper/reuslt.png)




