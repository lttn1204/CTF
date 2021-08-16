import pickle
with open('lost_baggage_enc.pickle','rb') as f:
	data=pickle.load(f)
c=data['cip']
pubkey=data['pbkey']
def decrypt(ct, pb):
	msg = ''
	for i in pb[::-1]:
		if ct >= i:
			msg += '1'
			ct -= i
		else:
			msg += '0'
	return bytes.fromhex(hex(int(msg, 2))[2:])
print(decrypt(c,pubkey))

