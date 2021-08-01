# Challenge
```py 
#!/usr/bin/env python3

from Crypto.Util import number
from Crypto.Cipher import AES
import os, sys, random
from flag import flag

def keygen():
	iv, key = [os.urandom(16) for _ in '01']
	return iv, key

def encrypt(msg, iv, key):
	aes = AES.new(key, AES.MODE_CBC, iv)
	return aes.encrypt(msg)

def decrypt(enc, iv, key):
	aes = AES.new(key, AES.MODE_CBC, iv)
	return aes.decrypt(enc)

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
	pr(border, " hi all, welcome to the simple KEYBASE cryptography task, try to    ", border)
	pr(border, " decrypt the encrypted message and get the flag as a nice prize!    ", border)
	pr(border*72)

	iv, key = keygen()
	flag_enc = encrypt(flag, iv, key).hex()

	while True:
		pr("| Options: \n|\t[G]et the encrypted flag \n|\t[T]est the encryption \n|\t[Q]uit")
		ans = sc().lower()
		if ans == 'g':
			pr("| encrypt(flag) =", flag_enc)
		elif ans == 't':
			pr("| Please send your 32 bytes message to encrypt: ")
			msg_inp = sc()
			if len(msg_inp) == 32:
				enc = encrypt(msg_inp, iv, key).hex()
				r = random.randint(0, 4)
				s = 4 - r
				mask_key = key[:-2].hex() + '*' * 4
				mask_enc = enc[:r] + '*' * 28 + enc[32-s:]
				pr("| enc =", mask_enc)
				pr("| key =", mask_key)
			else:
				die("| SEND 32 BYTES MESSAGE :X")
		elif ans == 'q':
			die("Quitting ...")
		else:
			die("Bye ...")

if __name__ == '__main__':
	main()
  ```
Khi ta nc vào server có 2 option là ```[G]et the encrypted flag``` và ```[T]est the encryption```

```[G]et the encrypted flag``` thì ta nhận được flag đã được mã hóa

```[T]est the encryption``` thì server yêu cầu ta nhập 32 bytes message và trả về:
      * ```key``` dùng để mã hóa nhưng mất đi 2 bytes cuối
      * ```encrypt``` của 32 bytes ta nhập nhưng chỉ được block cuối và 1 số bytes của block đầu tiên
Và 1 điều lưu ý nữa là ```key``` và ```iv``` mỗi lần nc là không đổi

Giả sử bây giờ mình gửi lên server 2 block 1 block 16 bytes ```a``` và 1 block 16 bytes ```b``` và nhận được 2 block encrypt là block1 và ```block2```

Vì key chỉ bị mất đi 2 bytes nên đầu tiên mình sẽ brute force để tìm lại 2 bytes. Bằng cách dùng key này để decrypt block thứ 2 của ```enc_flag``` rồi xor lại với e
block thứ nhất của ```enc_flag``` xem cái nào có khả năng là ```flag``` ( kêt thúc bằng "}" chẵn hạn :3 ) , bằng cách này thì mình có thể tìm được block 2 của flag và ```key```

Để tìm iv thì mình phải tìm được ```block1```. Cũng đơn giản thôi vì đã có key và block 2 vày key ta chỉ cần decrypt ```block2``` và xor lại với 16 bytes 'b'

Tìm lại iv cũng tương tự bằng cách decrypt block1 và xor lại với 16 bytes 'a' là ta sẽ tìm được ```v```.

Có ```iv``` và ```key```, giải mã v
