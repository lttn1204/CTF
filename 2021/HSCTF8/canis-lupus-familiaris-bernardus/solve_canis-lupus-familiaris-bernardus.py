from pwn import *
def valid(str1):
    v = list("ABCDEFGHIKLMNPQRSTVWYZ")
    for i in str1:
        if i not in v:
            return 0,i,str1.index(i)
    return 1,i,str1.index(i)
    
def flip(iv,char,i):
	char_flip=iv[i*2:(i+1)*2]
	char_flip=xor(bytes.fromhex(char_flip),char)
	char_flip=xor(char_flip,b"A")
	return iv[:i*2]+char_flip.hex()+iv[(i+1)*2:]


p=connect("canis-lupus-familiaris-bernardus.hsc.tf", 1337)
p.recvuntil(b'valine: V\n')
for i in range(100):
	print(i)
	question=p.recv()
	question=question.strip()
	print(f"question: {question}")
	s=question[3:19]
	print(s)
	a,b,c=valid(s.decode())
	if a==1:
		p.sendline("T")
		print("T")
		result=p.recvline()
		print(result)
	elif a==0:

		p.sendline("F")
		print("F")
		p.recvline()
		tmp=p.recvline().strip()
		print(tmp)
		iv=tmp[15:].decode()
		print(iv)
		p.recv()
		new_iv=(flip(iv,b,c))
		p.sendline(new_iv)
		print(new_iv)
		tmp=p.recvline()
		print(tmp)

tmp=p.recvline()
flag=p.recvline()
print(tmp)
print(flag)

