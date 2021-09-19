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

Ta dễ dàng tìm lại m b đầu

```py
from Crypto.Util.number import *
from Crypto.Util.Padding import pad
from gmpy2 import *
c=open('chal.enc','rb').read()
n=30004084769852356813752671105440339608383648259855991408799224369989221653141334011858388637782175392790629156827256797420595802457583565986882788667881921499468599322171673433298609987641468458633972069634856384101309327514278697390639738321868622386439249269795058985584353709739777081110979765232599757976759602245965314332404529910828253037394397471102918877473504943490285635862702543408002577628022054766664695619542702081689509713681170425764579507127909155563775027797744930354455708003402706090094588522963730499563711811899945647475596034599946875728770617584380135377604299815872040514361551864698426189453
f = open("chal.py","rb").read()
cipher=[]
for a in range(0,len(f),256):
	tmp1 = f[a:a+256]
	if len(tmp1) < 256:tmp1 = pad(tmp1, 256)
	tmp1 = bytes_to_long(tmp1)
	tmp2=c[a:a+256]
	tmp2 = bytes_to_long(tmp2)
	tmp=tmp1^tmp2
	cipher.append(tmp1^tmp2)
  
print(cipher)
e1,e2=65537,65539
c1,c2=cipher[0],cipher[1]
a,b=gcdext(e1,e2)[1:]
flag=long_to_bytes(pow(c1,a,n)*pow(c2,b,n)%n)
print(flag)
```
