

from pwn import *
p=connect('34.125.6.66', 5000)
p.recvline()
p.recvline()
p.recvline()
encrypted=p.recvline()[11:-1]
print(encrypted)
signature=p.recvline()[11:-1]
print(signature)
p.recvuntil(b'Your choice: ')
print(len(encrypted))
iv=bytes.fromhex(encrypted[:32].decode())
data=bytes.fromhex(encrypted[32:].decode())
print(iv,data)

msg=b'guest\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b'
#Flipping IV
tmp=iv
new_iv=xor(tmp,b'royal\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b')
new_iv=xor(new_iv,b'guest\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b\x1b')
new_encrypted=new_iv+data
new_encrypted=new_encrypted.hex()
print(len(new_encrypted),len(encrypted))
print(new_encrypted)
payload=b'name=player101&role='+new_encrypted.encode()
########################
#F
p.sendline('3')
p.recvuntil(b'Your data:')
p.sendline(b'6'*64+payload)
t1=p.recvline()[7:-1]
print(t1)
p.recvuntil(b'Your choice: ')
p.sendline('3')
p.recvuntil(b'Your data:')
p.sendline(b'\\'*64+bytes.fromhex(t1.decode()))
t2=p.recvline()[7:-1]
print(t2)
#########
#GET FLAG
p.recvuntil(b'Your choice: ')
p.sendline('1')
p.recvuntil(b'Your data: ')
p.sendline(payload+b'&sign='+t2)
print(p.recvline())
print(p.recvline())
print(p.recvline())


