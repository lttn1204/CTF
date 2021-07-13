# Challenge

```py
#!/usr/local/bin/python

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from random import randint
from binascii import hexlify

with open('flag.txt','r') as f:
    flag = f.read().strip()

with open('keyfile','rb') as f:
    key = f.read()
    assert len(key)==32

'''
Pseudorandom number generators are weak!
True randomness comes from phyisical objects, like dice!
'''
class TrueRNG:

    @staticmethod
    def die():
        return randint(1, 6)

    @staticmethod
    def yahtzee(N):
        dice = [TrueRNG.die() for n in range(N)]
        return sum(dice)

    def __init__(self, num_dice):
        self.rolls = num_dice

    def next(self):
        return TrueRNG.yahtzee(self.rolls)

def encrypt(message, key, true_rng):
    nonce = true_rng.next()
    cipher = AES.new(key, AES.MODE_CTR, nonce = long_to_bytes(nonce))
    return cipher.encrypt(message)

'''
Stick the flag in a random quote!
'''
def random_message():
    NUM_QUOTES = 25
    quote_idx = randint(0,NUM_QUOTES-1)
    with open('quotes.txt','r') as f:
        for idx, line in enumerate(f):
            if idx == quote_idx:
                quote = line.strip().split()
                break
    quote.insert(randint(0, len(quote)), flag)
    return ' '.join(quote)

banner = '''
============================================================================
=            Welcome to the yahtzee message encryption service.            =
=  We use top-of-the-line TRUE random number generators... dice in a cup!  =
============================================================================
Would you like some samples?
'''
prompt = "Would you like some more samples, or are you ready to 'quit'?\n"

if __name__ == '__main__':
    NUM_DICE = 2
    true_rng = TrueRNG(NUM_DICE)
    inp      = input(banner)
    while 'quit' not in inp.lower():
        message = random_message().encode()
        encrypted = encrypt(message, key, true_rng)
        print('Ciphertext:', hexlify(encrypted).decode())
        inp = input(prompt)
```
Mõi lần ta input thì server sẽ trả về AES-CTR encrypt của ouput random_message() với key là không đổi và nonce là output của TrueRNG

### Phân tích 1 chút :
* Hàm **next()** của **TrueRNG** đơn giản sẽ trả về 1 số random từ 0 -> 12 làm giá trị nonce cho AES-CTR encrypt
* **random_message()** sẽ lấy ngẫu nhiên 1 quotes (trong tổng số 25 quotes) và chèn **flag** vào vị trí bất kì trong quotes ấy
* Khi encrypt AES-CTR cũng giống như OTP, tức là sẽ **xor** **plaintext** với 1 đoạn ngâu nhiên dựa vào **key** và **nonce**, giã sử mã hóa 2 message với cùng 1  **key** và **nocne** thì đồng nghĩ với việc xor 2 message với cùng 1 key (khác với key ở trên nhé)
* key của AES-CTR không đổi trong mỗi lần connect

## Ý tưởng 
Vì next() chỉ trả về từ 0 -> 12 và chỉ có 25 quotes thôi nên mình có thể brute force request thật nhiều lên Server để nhận lại nhiều output. Lúc này trong cái đống output ấy cũng sẽ có cái được encrypt chung 1 key (random ra cùng 1 nonce)  và được lấy từ chung quotes :)

Check thử thì thấy các output có tổng cộng 25 độ dài khác nhau, vậy tức là không có quotes nào có chung độ dài ( AES-CTR encrypt không làm thay đổi độ dài),nên dễ dàng biết cái nào la encrypt của chung 1 quotes

Tiếp theo xor 2 quotes có cùng độ dài với nhau, nếu ra được nhiều  b'\x00' thì chúng được mã hóa chung 1 key. Lúc này sẽ có 1 không phải b'\x00' vì đoạn này chinh là flag đã được chèn vào.

Lúc này với mỗi quotes ban đầu ta có được các ouput của quotes ấy được encrypt với cùng 1 key

Mình sẽ gọi quotes ban đầu từ quotes1 -> quotes25 cho dễ hiểu nhé

Bây giờ giá sử với quotes1 mình sẽ chọn 2 ouput đã tìm được ở trên được mã hóa cùng 1 key. Xor 2 ouput ấy sẽ ra được rất nhiều b'\x00' và có 1 đoạn không phải b'\x00' mình tam gọi đoạn này là **xored1**

Lúc này **xored1** = **flag** xor **1 đoạn của quotes1**, vì mình biết được flag format là ***flag{*** nên mình  xor **xored1** với **flag{**, lúc này mình sẽ ra được 5 chữ cái english nào đó có thể thành từ được ( vì là quotes mà :) ) rồi sau đó tiếp tục đoán xem các chữ cái tiếp theo là gì và xor ngược lại với **xored1**để tìm được các kí tự tiếp theo của flag: 

Ví dụ ``` 'flag{' ^ xored1 = 'You c'``` thì mình đoán chữ ấy có thể là  ```You can ``` , rồi lại lấy ``` You can ``` xor ngược lại  **xored1** . Cứ làm như thế đến khi không đoán được nữa thì chuyển qua làm với **xored2** ( tương tự xored1 nhưng với quotes2) , lúc này không cần làm lại tmà cứ lấy đoạn flag vừa tìm được để xor và tìm các kí tự tiếp theo, đén khi không đoán được thì lại chuyển sang quotes khác ...

Làm như thế đến khi nào ra flag thì dừng :)

### Vì bài này mình làm đa số bằng tay nên mình chỉ ghi lại ý tưởng thôi nha :D



