# Challenge

``` py
#!/usr/bin/env python3
import sys
import shlex
import subprocess
from Cryptodome.PublicKey import ECC
from Cryptodome.Hash import SHA3_256
from Cryptodome.Math.Numbers import Integer
import time 
# util

def run_cmd(cmd):
    try:
        args = shlex.split(cmd)
        return subprocess.check_output(args).decode('utf-8')
    except Exception as ex:
        return str(ex)


def read_message():
    return sys.stdin.readline()


def send_message(message):
    sys.stdout.write('### {0}\r\n>'.format(message))
    sys.stdout.flush()

# crypto stuff

def hash(msg):
    h_obj = SHA3_256.new()
    h_obj.update(msg.encode())
    return Integer.from_bytes(h_obj.digest())


def setup(curve):
    key = ECC.generate(curve=curve),
    return key


def blind(msg, pub):
    r = pub.pointQ * hash(msg)
    return r


def sign(r, key):
    r_prime = r * key.d.inverse(key._curve.order)

    date = int(time.time())
    nonce = Integer.random_range(min_inclusive=1,max_exclusive=key._curve.order)
    z = f'{nonce}||{date}'


    R = r_prime + (key._curve.G * hash(z))
    s = (key.d - hash(z)) % key._curve.order
    # return (R, s, z)
    # we can not give away z or this is unsafe: x = s+h(z)
    return R, s


def verify(msg, sig, pub):
    R, s = sig

    if s in [0,1,''] and s > 0:
        return False

    tmp1 = s * pub._curve.G
    tmp2 = - pub.pointQ 
    tmp3 = tmp2 + R

    return tmp1 + tmp3 == hash(msg) * pub._curve.G


## ok ok here we go

def main():
    while True:
        send_message('Enter your command:')
        cmd = read_message().strip()

        if cmd == 'sign':
            send_message('Send cmd to sign:')
            cmd = read_message().strip()

            if(cmd in ['id', 'uname', 'ls', 'date']):
                r = blind(cmd, pubkey)
                sig = sign(r, key)
                
                send_message(f'Here you go: {sig[0].x}|{sig[0].y}|{sig[1]}|{cmd}')
            else:
                send_message('Not allowed!')

        elif cmd == 'run':
            send_message('Send sig:')
            sig = read_message().strip()
            tmp = sig.split('|')
            if len(tmp) == 4:
                x = int(tmp[0])
                y = int(tmp[1])
                s = int(tmp[2])
                c = tmp[3]
                sig = (ECC.EccPoint(x, y, curve='P-256'), s)
                if(verify(c, sig, pubkey)):
                    out = run_cmd(c)
                    send_message(out)
                else:
                    send_message('Invalid sig!')
            else:
                send_message('Invalid amount of params!')

        elif cmd == 'show':
            send_message(pubkey)

        elif cmd == 'help':
            send_message('Commands: exit, help, show, run, sign')

        elif cmd == 'exit':
            send_message('Bye :) Have a nice day!')
            break

        else:
            send_message('Invalid command!')


if __name__ == '__main__':
    key = setup('P-256')
    pubkey = key.public_key()
    main()
```

1 Bài ECC cho phép chúng ta run các command nếu có được các signature của command ấy

Đề cũng cho sẵn chúng ta signature của 4 command  ```'id', 'uname', 'ls', 'date'```


![](https://github.com/lttn1204/CTF/blob/main/2021/Hack.lu/image/p7.png)

Như vậy có thể thấy nếu muốn flag thì ta phải có signature của các command đọc flag :D ```cat flag``` chẳng hạn

Ban đầu mình chú ý tới các dòng
```py
date = int(time.time())
nonce = Integer.random_range(min_inclusive=1,max_exclusive=key._curve.order)
z = f'{nonce}||{date}'
```
Nhìn vào mình nghĩ ngay tới bias nonce và trong đầu mình kiểu : "Thấy mẹ ròi, lại lattice à 😥"

Nhưng sau 1 lúc xem kĩ thì mình thấy lúc tính server sử dụng SHA(z) để tính và SHA(z) cùng với order của curve cũng là 256 bit nên mình nghĩ chắc không phải (hoặc có lẽ phải nhưng mình không nhìn ra :((  )

Lúc này mình tìm đến nhưng chổ khác và mình thấy bài này không khó như mình tưởng :v


Nhìn vào hàm ```sign``` và ```verify```

Giả sử pubkey là G là secret là d và Q = d\*G và z sinh ra từ 3 dòng ở trên

Ví dụ ta muốn sign 1 message m, server sẽ làm như sau:

![](https://github.com/lttn1204/CTF/blob/main/2021/Hack.lu/image/p5.png)

![](https://github.com/lttn1204/CTF/blob/main/2021/Hack.lu/image/p6.png)

Signaturec sẽ có dạng ```R(x)||R(y)||S||m```

Ok bây giờ mình sẽ forge signature của  ```cat flag``` từ signature của ```ls```

Từ server mình sẽ  có được signatrue của ```ls```, tức là mình đã có được các tham số sau:
* G có sẵn
* R và S từ signature
* SHA(m)

Vì công thức verify chỉ tính 

![](https://github.com/lttn1204/CTF/blob/main/2021/Hack.lu/image/p9.png)
 
Nên vế phải ta hoàn toàn tính được

vậy nhiệm vụ là cần tìm R vs S mới sao cho

![](https://github.com/lttn1204/CTF/blob/main/2021/Hack.lu/image/p10.png)

Vì vế phải của cả 2 signature ta đề có thể tính được nên ta cũng sẽ tính được giá trị X sao cho: ```SHA('cat flag') \* G -  SHA('ls') \* G ```









