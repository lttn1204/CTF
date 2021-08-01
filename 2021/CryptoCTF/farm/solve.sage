from sage.all import *
import string, base64, math
from base64 import *
ALPHABET = string.printable[:62] + '\\='
F = list(GF(64))

def maptofarm(c):
	assert c in ALPHABET
	return F[ALPHABET.index(c)]

def decrypt(key,c):
	flag=""
	for i in c:
		for m in ALPHABET.encode():
			if ALPHABET[F.index(key * maptofarm(chr(m)))]==i:
				flag+=chr(m)
	try:
		flag=b64decode(flag)
		return flag
	except:
		return flag.encode()


for key in F:
	flag=decrypt(key,'805c9GMYuD5RefTmabUNfS9N9YrkwbAbdZE0df91uCEytcoy9FDSbZ8Ay8jj')
	if b'CCTF' in flag:
		print(flag)
	
