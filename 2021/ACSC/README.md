# RSA stream

```py
import gmpy2
from Crypto.Util.number import long_to_bytes, bytes_to_long, getStrongPrime, inverse
from Crypto.Util.Padding import pad

from flag import m
#m = b"ACSC{<REDACTED>}" # flag!

f = open("chal.py","rb").read() # I'll encrypt myself!
print("len:",len(f))
p = getStrongPrime(1024)
q = getStrongPrime(1024)

n = p * q
e = 0x10001
print("n =",n)
print("e =",e)
print("# flag length:",len(m))
m = pad(m, 255)
m = bytes_to_long(m)

assert m < n
stream = pow(m,e,n)
cipher = b""

for a in range(0,len(f),256):
  q = f[a:a+256]
  if len(q) < 256:q = pad(q, 256)
  q = bytes_to_long(q)
  c = stream ^ q
  cipher += long_to_bytes(c,256)
  e = gmpy2.next_prime(e)
  stream = pow(m,e,n)

open("chal.enc","wb").write(cipher)
```
Phân tích 1 chút:

* Đầu tiên đề tạo ra các tham p,q,n như các bài RSA thông thường

* Tiếp theo đề đọc lại chính file ```chall.py```rồi chia thành 3 block = nhau và đều là 256 bytes.

* Cuối cùng thì mỗi block sẽ được xor với encrypt của flag với 3 số mũ e khác nhau lần lượt là 65537,65537 và 65543 ròi ghi vào file ```chal.enc```


Vậy với việc đọc lại file ```chal.py``` và chia thành 3 blocks giống như đề và xor lại với 3 block của file ```chall.enc``` , mình dễ dàng tìm được 3 ciphertext của encrypt RSA với 3 số mũ e khác nhau cùng n

Đến đây ta thấy cả 3 ciphertext đều encrypt với cùng 1 n và chỉ khác e -> commond modulus attack

Đầu tiên dùng thuật toán Euclid mở rộng tìm 2 số a và b sao cho: ```a*e1+ b*e2 = 1```

Lúc này:

![](https://github.com/lttn1204/CTF/blob/main/2021/ACSC/image.png)

