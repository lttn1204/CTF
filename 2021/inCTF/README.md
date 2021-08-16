# Gold_digger
```py
import random
from Crypto.Util.number import *
from gmpy2 import *

flag=open("flag","rb").read()

def encrypt(msg, N,x):
    msg, ciphertexts = bin(bytes_to_long(msg))[2:], []
    for i in msg:
        while True:
            r = random.randint(1, N)
            if gcd(r, N) == 1:
                bin_r = bin(r)[2:]
                c = (pow(x, int(bin_r + i, 2), N) * r ** 2) % N
                ciphertexts.append(c)
                break
    return ciphertexts

N = 76412591878589062218268295214588155113848214591159651706606899098148826991765244918845852654692521227796262805383954625826786269714537214851151966113019

x = 72734035256658283650328188108558881627733900313945552572062845397682235996608686482192322284661734065398540319882182671287066089407681557887237904496283

flag = (encrypt(flag,N,x))

open("handout.txt","w").write("ct:"+str(flag)+"\n\nN:"+str(N)+"\n\nx:"+str(x))
```
Đề cho ta x,N và 1 mảng c rất dài 

Đọc code thì thấy đề encrypt theo mỗi giá trị binary của flag 

Nếu tại bin(flag) =='0' thì : 

![](https://github.com/lttn1204/CTF/blob/main/2021/inCTF/image/ct1.png)

Còn nếu tại bin(flag)=='1':

![](https://github.com/lttn1204/CTF/blob/main/2021/inCTF/image/ct2.png)

Dễ thấy nếu ```bin(flag)[i] =='0'``` thì sẽ tồn tại căn bậc 2 modulo N của c[i], Ngược lại nếu ```bin(flag)[i] =='1'``` thì sẽ không tồn tại căn bậc 2 modulo N của c[i]

Dựa vào điểm này mình sẽ dùng ```jacobi symbol``` để kiểm tra xem từng vị trí của mảng có tồn tại căn bậc  2 modulo N hay không, từ đó có thể tìm lại lần lượt các bit của flag.

đây là [solution](https://github.com/lttn1204/CTF/blob/main/2021/inCTF/resource/solve_gold_digger.py) của mình 
