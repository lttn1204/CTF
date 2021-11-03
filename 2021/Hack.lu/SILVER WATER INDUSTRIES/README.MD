# Challengge

Đầu tiên mình nc vào server thử 

![](https://github.com/lttn1204/CTF/blob/main/2021/Hack.lu/image/p1.png)

Chẳng tháy nói gì, chỉ hiện lên 1 số nào đó và 20 mảng mỗi mảng lại có 8 con số 

OK báy giờ mình sẽ đọc source

``` go
package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"os"
)

func genN() *big.Int {
	var p *big.Int
	var q *big.Int
	var err error

	for {
		p, err = rand.Prime(rand.Reader, 64)
		if err != nil {
			panic(err)
		}
		res := new(big.Int)
		if res.Mod(p, big.NewInt(4)); res.Cmp(big.NewInt(1)) == 0 {
			break
		}
	}

	for {
		q, err = rand.Prime(rand.Reader, 64)
		if err != nil {
			panic(err)
		}
		res := new(big.Int)
		if res.Mod(q, big.NewInt(4)); res.Cmp(big.NewInt(3)) == 0 {
			break
		}
	}

	N := new(big.Int)
	N.Mul(p, q)
	return N
}

func genX(N *big.Int) *big.Int {
	for {
		x, err := rand.Int(rand.Reader, N)
		if err != nil {
			panic(err)
		}
		g := new(big.Int)
		g.GCD(nil, nil, x, N)
		if g.Cmp(big.NewInt(1)) == 0 {
			return x
		}
	}
}

func encryptByte(b uint8, N *big.Int) []*big.Int {
	z := big.NewInt(-1)
	enc := make([]*big.Int, 8)
	for i := 0; i < 8; i++ {
		bit := b & uint8(math.Pow(2, float64(7-i)))
		x := genX(N)
		x.Exp(x, big.NewInt(2), N)
		if bit != 0 {
			x.Mul(x, z)
			x.Mod(x, N)
		}
		enc[i] = x
	}
	return enc
}

func generateRandomString(n int) string {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			panic(err)
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret)
}

func main() {
	N := genN()

	token := []byte(generateRandomString(20))

	fmt.Println(N)
	for _, b := range token {
		fmt.Println(encryptByte(uint8(b), N))
	}
	fmt.Println("")

	reader := bufio.NewReader(os.Stdin)

	input, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}
	input = input[:len(input)-1]

	if string(token) == input {
		fmt.Println("flag{<YOUR_FLAG_HERE>}")
	}
}
```

Vì không quen với go nên mình đọc bài này hơi lâu :((

Để dễ hình dung thì:
* GenN() trả về 1 số nguyên N là tích của 2 số nguyên tố, N khá nhỏ nên có thể factor được
* GenX() trả về 1 số nguyên X<N và gcd(X,N)=1
* generateRandomString() đơn giản tạo ra 1 chuỗi ngẫu nhiên 20 kí tự trong ```letter```

flow của đề như sau: 
* Gen ra ```N``` bằng GenN()
* Gen ra ```token``` bằng generateRandomString()
* encryptBytes()  lần lượt các kí tự trong ```token``` với ```N```
* Cho chúng ta ```N``` và kết quả sau khi encrypt, nếu chúng ta recover lại được ```token``` và gửi lại thì có flag :D

Như vậy thì số đầu tiên nhận được khi nc vào server chính là ```N```, 20 mảng phía sau chính là 20 két quả sau khi encrypt của các kí tự trong ```token```

OK vậy giờ muốn recover lại được token, mình cần phải biết hàm encrypt() nó làm gì :

Để dễ nhìn mình viết lại hàm encrypt() bằng python như sau

``` py
def encryptByte(b,N):
	z=-1
	enc=[]
	for i in range(8):
		bit=ord(b) & pow(2,7-i)
		x=genX(N)
		x=pow(x,2,N)
		if bit!=0:
			x=(x*z)%N
		enc.append(x)
	return enc
```

Nhìn vào dễ dàng thấy được các giá trị trong mảng trả về tương ứng với vị trí các bit trong ```b``` và sẽ có 2 trường hợp:
* Là căn bậc 2 modulo ```N``` nếu bit của ```b``` tại vị trí đó là 0
* Không là căn bặc 2 modulo ```N``` nếu bit của ```b``` tại vị trí đó là 1

Vậy giả sử nếu chúng ta có thể xác đinh được số nào là căn bậc 2 modulo N thì từ đó có thể dễ dàng suy ra được bit của ```b``` tại vị trí đó :d -> jacobi symbol :D

``` py
from sock import *
from gmpy2 import *
p=Sock('flu.xxx', 20060)
n=int(p.recvline())
print(f"N: {n}")
def filter(s):
	arr=[]
	s=s.split(b' ')
	for i in range(len(s)):
		if i==0:
			tmp=s[i][1:]
			arr.append(int(tmp))
		elif i==7:
			tmp=s[i][:-2]
			arr.append(int(tmp))
		else:
			arr.append(int(s[i]))
	print(arr)
	return arr
	

def decrypt(nums):
	arr=[]
	for num in nums:
		if  jacobi(num,n)==1:
			arr.append(0)
		else:
			arr.append(1)
	return chr(int("".join([str(x) for x in arr]),2))	
token=''
for _ in range(20):
	arr=p.recvline()
	arr=filter(arr)
	token+=decrypt(arr)
	print(token)
print(p.recvline())

p.sendline(token)
print(p.recvline())

```



