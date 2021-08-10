from pwn import *
def cat(x):
	p=connect('104.199.9.13', 1338)
	p.recvuntil(b'[plaintext (hex)]>  ')
	p.sendline(x.hex())
	p.recvuntil(b'[ciphertext (hex)]> ')
	result=p.recvline().decode()
	return bytes.fromhex(result)
flag=b''	
for i in range(32,0,-1):
	enc=cat(b'a'*i)
	tmp=xor(enc[32],enc[0])
	flag+=xor(b'a',tmp)
	print(flag)
enc=cat(b'a'*32)
key=xor(enc[32:64],flag)
flag+=xor(enc[64:71],key[:7])
print(flag)

#flag=b'BSNoida{how_can_you_break_THE_XOR_?!?!}'	

