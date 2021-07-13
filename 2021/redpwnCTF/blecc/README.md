# Challenge
Đề bài cho ta 1 file:
```
p = 17459102747413984477
a = 2
b = 3
G = (15579091807671783999, 15579091807671783999)
Q = (8859996588597792495, 2628834476186361781)
d = ???
Can you help me find `d`?
Decode it as a string and wrap in flag format.
```
Thấy đây tham số của 1 ECC với 2 điểm P và Q.

Vì **p** không lớn nên ta có thể dễ tính **d** = **discrete_log()** của sage.

Nhưng khi tạo các điểm thì:

![](https://github.com/lttn1204/CTF/blob/main/2021/redpwnCTF/blecc/image1.png)

Điểm G không thể tạo được vì không nằm trong đường cong. Mình nghĩ đề cố tình cho sai điểm G nên mình sẽ tìm lại điểm G đúng.

Mình thử tìm là Gy từ Gx bằng **lift_x()**mà may mắn là đúng điểm G cần tim 

![](https://github.com/lttn1204/CTF/blob/main/2021/redpwnCTF/blecc/image2.png)


