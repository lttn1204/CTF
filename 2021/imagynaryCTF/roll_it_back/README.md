# Challenge

```py
from itertools import *
from gmpy2 import *
def x(a,b):
    return bytes(islice((x^y for x,y in zip(cycle(a), cycle(b))), max(*map(len, [a, b]))))
def t(x):
    return sum((((x & 28) >> 4) & 1) << i for i, x in enumerate(x))
T = t(x(b"jctf{not_the_flag}", b"*-*")) | 1
with open("flag.txt", "rb") as f:
    flag = int.from_bytes(f.read(), "little")
    l = flag.bit_length()
print(f"{l = }")


for _ in range(421337):
    flag = (flag >> 1) | ((popcount(flag & T) & 1) << (l - 1))
    
    
print(f"{flag = }")

### Output
# l = 420
# flag = 2535320453775772016257932121117911974157173123778528757795027065121941155726429313911545470529920091870489045401698656195217643
###
```
Nhìn vào đoạn đầu 1 xíu thì mình thấy code khá là loằng ngoằng với biến T được tạo từ 2 hàm ```x()``` và ```t()```. Thật ra mình không cần quan tâm đến 2 hàm này lắmvì các tham số  để tính T đều đã biết trước. Chỉ cần copy lại là có thể tính được T. 

Mình tính ra  T là : ```136085``` và bài cũng cho sẵn flag.bit_length()=```420```

Tiếp theo ta cần quan tâm đến đoạn: 
```py
for _ in range(421337):
    flag = (flag >> 1) | ((popcount(flag & T) & 1) << (l - 1))
```
Đoạn này mỗi lần lặp flag sẽ mất đi 1 bit cuối và nếu như tổng số bit của ```1```(flag&T) là số lẻ  thì ```flag``` sẽ được ```or``` với ```1<<419```

Ở đoạn tính ```flag``` ```or``` ```1<<419```  , vì flag đã mất 1 bit trước đó nên phép tính này đơn giản chỉ là thêm 1 bit ```1``` vào làm bit cao nhất của flag.

Đến đây có thể dễ dàng thấy được quy luật của bài này: Mỗi lần lặp flag mất đi 1 bit và nếu tổng số bit ```1``` của ```flag&T``` là lẻ thì thêm ```1``` vào làm bit cao nhất,
ngược lại thì thêm ```0``` vào làm bit cao nhất.

Lúc này mình có thể tìm tìm lai được flag ban đầu bằng cách dự đoán trước bit thấp nhất đã được bỏ đi ở mỗi lần lặp 
rồi check lại điều kiên bằng cách tính tổng số bit 1 của ```flag&T```. Nếu bit cao nhất của flag đang là 1 thì kết quả phải ra là số lẻ, ngược lại thì kết quả phải 
là chẵn và bỏ đi bit đầu tiên của flag. Cứ làm như thế đến khi đủ số lần lăp là tìm lại được flag ban đầu

[full_script](https://github.com/lttn1204/CTF/blob/main/2021/imagynaryCTF/roll_it_back/solve.py)
