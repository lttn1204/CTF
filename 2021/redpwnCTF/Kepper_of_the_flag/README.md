# Challenge
```py
#!/usr/local/bin/python3

from Crypto.Util.number import *
from Crypto.PublicKey import DSA
from random import *
from hashlib import sha1

rot = randint(2, 2 ** 160 - 1)
chop = getPrime(159)

def H(s):
    x = bytes_to_long(sha1(s).digest())
    return pow(x, rot, chop)


L, N = 1024, 160
dsakey = DSA.generate(1024)
p = dsakey.p
q = dsakey.q
h = randint(2, p - 2)
g = pow(h, (p - 1) // q, p)
if g == 1:
    print("oops")
    exit(1)

print(p)
print(q)
print(g)

x = randint(1, q - 1)
y = pow(g, x, p)

print(y)


def verify(r, s, m):
    if not (0 < r and r < q and 0 < s and s < q):
        return False
    w = pow(s, q - 2, q)
    u1 = (H(m) * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
    return v == r


pad = randint(1, 2 ** 160)
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
    k = (H(m) + pad + i) % q
    if k < 1:
        exit()
    r = pow(g, k, p) % q
    if r == 0:
        exit()
    s = (pow(k, q - 2, q) * (H(m) + x * r)) % q
    if s == 0:
        exit()
    print(H(m))
    print(r)
    print(s)

print("ok im done for now")
print("you visit the flag keeper...")
print("for flag, you must bring me signed message:")
print("'give flag':" + str(H(b"give flag")))

r1 = int(input())
s1 = int(input())
if verify(r1, s1, b"give flag"):
    print(open("flag.txt").readline())
else:
    print("sorry")
```
Đề cho ta 1 Server verify DSA. Chúng ta có thể input 2 lần khác nhau đẻ lấy 2 chữ kí và phải nhập lại chữ kí đúng của b"give flag" để có flag
Thông tin chúng ta có:  **p, q ,g, y**

Nếu chúng ta gửi 1 message lên để kí thì ta sẽ được **H(m),r,s**

Quan sát kĩ mọi thứ có vẻ bình thường  nhưng ```k = (H(m) + pad + i) % q```  hơi khác so với 1 DSA thông thường.

k trong DSA phải thật sư ngẫu nhiên để tranh việc bị lộ private key **x** vì nếu có k thì sẽ dễ dàng tim được x:

![](https://github.com/lttn1204/CTF/blob/main/2021/redpwnCTF/Kepper_of_the_flag/image1.png)

Nếu chúng ta có được **x** thì dễ dàng kí được message ```b'give flag'```

Quay lại nhìn vào Server, Server yêu cầu nhập 2 message khác nhau nhưng **k** được tính bằng cách ```Sha1(message) + pad + i```. Do pad là không đổi mỗi lần connect nên mình sẽ tìm cách nhập 2 message sao cho Sha1 của chúng giống nhau. Điều này hoàn toàn có thể vì Sha1 có collision và mình tìm thấy ở [shatted.io](https://shattered.io/) 2 file pdf có cùng sha1. Download file về và dùng nó để làm 2 message gửi lên server :)
Lúc này ta thấy **H(message1) = H(message2) = > k1+1=k2**

V

![](https://github.com/lttn1204/CTF/blob/main/2021/redpwnCTF/Kepper_of_the_flag/image2.png)

Ta có thể tính lại được k và tìm x nhờ công thức phía trên 
