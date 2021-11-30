

# Where  your ticket

## Challenge
```py
#nc 34.125.6.66 5000
from Crypto.Cipher import AES
from hashlib import md5
import hmac
from os import urandom
import sys
import random
from binascii import hexlify, unhexlify
import secret
import socket
import threading
import socketserver
import signal

host, port = '0.0.0.0', 5000
BUFF_SIZE = 1024

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
	allow_reuse_address = True
class ThreadedTCPRequestHandler(socketserver.StreamRequestHandler):

	def handle(self):
		self.AES_BLOCK_SIZE = 32
		self.SIG_SIZE = md5().digest_size
		self.message = b'guest'
		self.key = self._hash_key(secret.key)
		self.enc_role, self.sig = self.encrypt(self.message)

		try:
			while True:
				self.menu()

				try:
					self.request.sendall(b'Your choice: ')
					opt = int(self.rfile.readline().decode())
				except ValueError:
					self.request.sendall(
						b'Invalid option!!!\n')
					continue
				if opt == 1:
					self.request.sendall(b'Data format: name=player101&role=enc_role&sign=sig, enc_role and sign are in hex.\n')
					self.request.sendall(b'Your data: ')
					data = self.rfile.readline().strip()
					self.confirm(data)
				elif opt == 2:
					self.request.sendall(b'Your data: ')
					data = self.rfile.readline().strip()
					if b'&role=' in data:
						self.request.sendall(b'Not that easy!\n')
					else:
						sign = self.sign_new(data)
						if sign == None:
							pass
						else:
							self.request.sendall(b"Hash: " + hexlify(sign) + b'\n')
				elif opt == 3:
					self.request.sendall(b'Your data: ')
					data = self.rfile.readline().strip()
					sign = self.sign_old(data)
					self.request.sendall(b"Hash: " + hexlify(sign) + b'\n')
				elif opt == 4:
					self.request.sendall(b'Goodbye!\n')
					return
				else:
					self.request.sendall(b'Invalid option!!!\n')

		except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
			print("{} disconnected".format(self.client_address[0]))

	def menu(self):
		self.request.sendall(b'\nYour role: ' + self.decrypt(b'name=player101&role='+hexlify(self.enc_role), hexlify(self.sig)))
		self.request.sendall(b'\nEncrypted data of your role:')
		self.request.sendall(b'\nEncrypted: ' + hexlify(self.enc_role))
		self.request.sendall(b'\nSignature: ' + hexlify(self.sig) + b'\n')
		self.request.sendall(b'1. Verify your data:\n')
		self.request.sendall(b'2. Sign your data in new way:\n')
		self.request.sendall(b'3. Sign your data in old way:\n')
		self.request.sendall(b'4. Quit\n')

	def _hash_key(self, key):
		return md5(key).digest()
	
	def _initialisation_vector(self):
		return urandom(16)
	
	def _cipher(self, key, iv):
		return AES.new(key, AES.MODE_CBC, iv)

	def encrypt(self, data):
		iv = self._initialisation_vector()
		cipher = self._cipher(self.key, iv)
		pad = self.AES_BLOCK_SIZE - len(data) % self.AES_BLOCK_SIZE
		data = data + (pad * chr(pad)).encode()
		data = iv + cipher.encrypt(data)
		ss = b'name=player101&role=%s'%(hexlify(data))
		sig = self.sign_new(ss)
		return data, sig
		
	def decrypt(self, data, sig):
		if hexlify(self.sign_new(data)) != sig:
			self.request.sendall(b'Message authentication failed')
			return
		else:
			pos = data.rfind(b'&role=')
			data = unhexlify(data[pos+6:])
			iv = data[:16]
			data = data[16:]
			cipher = AES.new(self.key, AES.MODE_CBC, iv)
			data = cipher.decrypt(data)
			return data[:-data[-1]]

	def XR(self, a, b):
		len_max = len(a) if len(a) > len(b) else len(b)
		s = ''
		for i in range(len_max):
			h = hex(a[i%len(a)] ^ b[i%len(b)])[2:]
			if(len(h) < 2):
				s += '0' + hex(a[i%len(a)] ^ b[i%len(b)])[2:]
			else:
				s += hex(a[i%len(a)] ^ b[i%len(b)])[2:]
		return unhexlify(s.encode())

	def xor_key(self, a):
		if isinstance(a, str):
			a = a.encode()
		b = self.key
		s = b''
		if len(a) > len(b):
			s += self.XR(a[:len(b)], b) + a[len(b):]
		elif len(a) < len(b):
			s += self.XR(b[:len(a)], a) + b[len(a):]
		return s

	def sign_old(self, data):
		return md5(self.xor_key(data)).digest()

	def sign_new(self, data):
		return hmac.new(self.key, data, md5).digest()

	def confirm(self, data):
		if isinstance(data, str):
			data = data.encode('utf-8')
		pos_name = data.rfind(b'name=')
		pos_role = data.rfind(b'&role=')
		pos_sign = data.rfind(b'&sign=')
		if pos_role == -1 or pos_sign == -1 or pos_name == -1:
			self.request.sendall(b'\nInvalid data!\n')
			return
		enc_role = data[:pos_sign]
		sign = data[pos_sign + 6:]
		try:
			check = self.decrypt(enc_role, sign)
		except Exception:
			self.request.sendall(b'\nInvalid data!\n')
		if check == b'royal':
			self.request.sendall(b'\nFlag here: ' + secret.flag)
		elif check == b'guest':
			self.request.sendall(b'\nHello peasant!\n')
		elif check == None:
			self.request.sendall(b'\nYou\'re a intruder!!!\n')
		else:
			self.request.sendall(b'\nStranger!!!\n')

	def parse_qsl(self, query):
		m = {}
		parts = query.split(b'&')
		for part in parts:
			key, val = part.split(b'=')
			m[key] = val
		return m


def main():
	server = ThreadedTCPServer((host, port), ThreadedTCPRequestHandler)
	server_thread = threading.Thread(target=server.serve_forever)
	server_thread.daemon = True
	server_thread.start()
	print("Server loop running in thread:", server_thread.name)
	server_thread.join()

if __name__=='__main__':
	main()
  ```
  Bài này source code hơi dài ban đầu mình đọc cũng hơi rối :((
  
  Tóm gọn lại thì bài này cho ta 1 data có dạng :
  
  ``` "name=player101&role=" IV+AES_CBC.encrypt(IV,"guest") +"&sign=" HMAC.encrypt(cả đoạn trước đó)```
  
  Với key để encrypt AES và HMAC là giống nhau và HMAC trong trường hợp này là HMAC md5
  
  Để verify thì server đầu tiên sẽ kiểm tra HMAC xem có đúng không, tiếp theo sẽ decrypt phần phía sau role với IV để xác định xem role là gì
  
  Nhiệm vụ của chúng ta là phải giả mạo sao cho khi decrypt role ra được "royal" chứ không phải "guest" :D   
  
  Việc thay đổi từ "guest" thành "royal" sau khi decrypt khá đơn giản, vì ta có thể control được IV và biết được chính xác ouput nên chỉ cần fliping là có thể thay đổi dược ouput khi decrypt
  
  ![](https://github.com/lttn1204/CTF/blob/main/2021/ISITDTU-CTF/image/AES_CBC_decrypt.png)
  
  
 Ta biết block đầu tiên sau khi decrypt ra sẽ là ```b'guest\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b'``` (mình tạm đặt là M) và ta cũng xác định được ouput mới cần decrypt ra được là ```b'royal\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b'``` (mình tạm đặt là M')
 
 Ta chỉ cần lấy M xor với IV là có thể tìm ra được đoạn output khi chưa được xor với IV ( mình tạm goi là C) - > ```C = IV xor M```
 
 Lúc này IV mới được tính bằng cách: ``` new_IV = C xor M' ```
 
 VẬy chỉ cần thay đổi IV cũ thành new_IV là ta có thể dễ dàng làm cho role khi decrypt ra thành ```royal```
 
 Oke đã xong bước đầu tiên, việc còn lại là phải làm sao cho cái HMAC kia nó verify đúng nữa :v tức là ta phải tính được giá trị HMAC của
 
 ```"name=player101&role=" + new_IV+AES_CBC.encrypt(IV,"guest")``` ( mình ghi "guest" là tại vì nó vẫn giữ nguyên giá trị cũ, chứ thật ra khi decrypt nó sẽ ra "royal" :(( )
 
 Nhìn lại source code thì đề co ta 2 option là ```sign_new``` và ```sign_old``` 
 
 ```sign_new``` sẽ tính luôn HMAC mà ta input vào, nhưng mà input lại không được chứa "&role=", xem ra hàm này cũng không giúp được gì
 
 Mình nhìn xuống tiếp vào  ```sign_old``` thì option này sẽ xor key với lại input của chúng ta xong rồi md5 lại
 ``` py
 def sign_old(self, data):
		return md5(self.xor_key(data)).digest()
 ```
 Nhưng hàm xor_key có hơi "bất thường", mình chạy code thử nhé:
 
 ```py
 from binascii import hexlify, unhexlify	
def XR( a, b):
	len_max = len(a) if len(a) > len(b) else len(b)
	s = ''
	for i in range(len_max):
		h = hex(a[i%len(a)] ^ b[i%len(b)])[2:]
		if(len(h) < 2):
			s += '0' + hex(a[i%len(a)] ^ b[i%len(b)])[2:]
		else:
			s += hex(a[i%len(a)] ^ b[i%len(b)])[2:]
	return unhexlify(s.encode())


def xor_key( a):
	if isinstance(a, str):
		a = a.encode()
	b = key
	s = b''
	if len(a) > len(b):
		s += XR(a[:len(b)], b) + a[len(b):]
	elif len(a) < len(b):
		s += XR(b[:len(a)], a) + b[len(a):]
	return s


key=b'lttnlttn'
data='lttnlttnahihihihihihihi'
print(xor_key(data)) 
```

Ví dụ xor như trên , kết quả sẽ ra là: 

![](https://github.com/lttn1204/CTF/blob/main/2021/ISITDTU-CTF/image/pic1.png)
  
 Ta thấy nếu độ dài giữa key và data khác nhau, hàm này chỉ xor cho dến vị trí cuối cùng của bên ngắn hơn, đoạn còn lại thì sẽ đem phần còn lại của bên dài hơn xuống :d
 
 Oke coi như đã thấy dc 1 cái gì đó, tiếp theo minh sẽ xem mã giả của HMAC 
 ````py
 function hmac is
    input:
        key:        Bytes    // Array of bytes
        message:    Bytes    // Array of bytes to be hashed
        hash:       Function // The hash function to use (e.g. SHA-1)
        blockSize:  Integer  // The block size of the hash function (e.g. 64 bytes for SHA-1)
        outputSize: Integer  // The output size of the hash function (e.g. 20 bytes for SHA-1)
 
    // Keys longer than blockSize are shortened by hashing them
    if (length(key) > blockSize) then
        key ← hash(key) // key is outputSize bytes long

    // Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
    if (length(key) < blockSize) then
        key ← Pad(key, blockSize) // Pad key with zeros to make it blockSize bytes long

    o_key_pad ← key xor [0x5c  blockSize]   // Outer padded key
    i_key_pad ← key xor [0x36  blockSize]   // Inner padded key

    return  hash(o_key_pad ∥ hash(i_key_pad ∥ message))
    ```
    
    
 
 
  
  
