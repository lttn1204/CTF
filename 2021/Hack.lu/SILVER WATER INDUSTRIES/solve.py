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

			
