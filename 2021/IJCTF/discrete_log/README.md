# Challenge
Đề bài cho 1 sever tính discrete log với mod cho trước cho phép chung ta nhập base và number cùng với flag được encrypt  RSA với số mũ là
65537 và mobằng với mod của discrete log

![](https://github.com/lttn1204/CTF/blob/main/2021/IJCTF/discrete_log/1.png)

Mình tạm gọi mod là ```n``` và encrypt flag là ```c```

Vậy mỗi khi ta nhập base và number để server tính discrete log thì server sẽ tính x sao cho

![](https://github.com/lttn1204/CTF/blob/main/2021/IJCTF/discrete_log/2.png)

Trong khi đó để decrypt được flag thì ta phải tìm ```d``` sao cho 

![](https://github.com/lttn1204/CTF/blob/main/2021/IJCTF/discrete_log/3.png)

Như vậy giả sử mình encrypt một giá trị khác đã biết trước bằng RSA (gọi là ```m1```) với số mũ là 65537 và mod vẫn là n như trên thì ta sẽ được ```c1``` sao cho 

![](https://github.com/lttn1204/CTF/blob/main/2021/IJCTF/discrete_log/4.png)

Lúc này mình gửi base là ```c1``` và number là ```m1``` lên dể server tính discrete log thì server sẽ tìm được x sao cho 

![](https://github.com/lttn1204/CTF/blob/main/2021/IJCTF/discrete_log/5.png)

Lúc này dễ dàng thấy ```x``` chính là giá trị ```d``` cần tìm để decrypt được c phía trên , 

[scrips](https://github.com/lttn1204/CTF/blob/main/2021/IJCTF/discrete_log/solve_discrete_log.py)
