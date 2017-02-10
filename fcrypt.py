from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import sys 
import getopt #TO accept the arguements to the python file
import os # to generate key and IV

def main(argv):
	global backend, d_key, s_key, cipher_file, plain_text, output_plain_text, signature2
	d_key = sys.argv[2]
	s_key = sys.argv[3]
	try:
		opts, args = getopt.getopt(argv, "ed", [])
	except getopt.GetoptError:
		print 'Invalid Arguement for Encryption use -e for decryption use -d'
		sys.exit()
	for opt, arg in opts:
		if opt == '-e':
			plain_text = sys.argv[4]
			signature2 = sys.argv[5]
			encrypt()
		if opt == "-d":
			signature2 = sys.argv[4]
			plain_text = sys.argv[5]
			decrypt()
			
def encrypt():
#Serialization of Private Key
	with open(s_key, "rb") as key_file:
        	private_key = serialization.load_pem_private_key(key_file.read(),password=None,backend=default_backend())

#Creating a signer to sign the message using AES	
	signer = private_key.signer(padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
#Encryption of Data using Symmetric Algorithm
	key = os.urandom(16)
	iv = os.urandom(16)
	word = os.urandom(16)
	cipher_text = ''
	cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
	encryptor = cipher.encryptor()
	encryptor.authenticate_additional_data(word)
#Opening the plain_text and signing and encrypting the data
	f = open(plain_text, "rb")
	for line in f.readlines():
	       	signer.update(line)
	f = open(plain_text, "rb")
	plaint = f.read()

	signature = signer.finalize()
#	encryptor.finalize()
	
	if len(plaint) % 16 == 0:
        	cipher_text = encryptor.update(plaint) + encryptor.finalize()
	else:
        	while len(plaint) % 16 == 0:
                	plaint += '0'
		cipher_text = encryptor.update(plaint) + encryptor.finalize()
#	encryptor.finalize()
	tag = encryptor.tag
#Using the public key to encrypt the symmetric key shared
	with open(d_key, "rb") as key_file:
                public_key = load_pem_public_key(key_file.read(), backend=default_backend())
#Encrypting the Symmetric Key
	ciphertext = public_key.encrypt(key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
	f = open(signature2, "w")
	f.write(ciphertext)
	f.write("eNd") #Using Delimiter to split the text signature, key and IV during decryption
	f.write(signature)
	f.write("eNd")
	f.write(iv)
	f.write("eNd")
	f.write(cipher_text)
	f.write("eNd")
	f.write(tag)
	f.write("eNd")
	f.write(word)
	
def decrypt():
#loading the senders public key
	with open(s_key, "rb") as key_file:
		public_key = load_pem_public_key(key_file.read(), backend=default_backend())
	
	sig = open(signature2, "rb").read()
#Splitting the cipher text based into cipher_data, Key, IV and signature
	signature3 = sig.split("eNd")
#Loading and serializing the private key of destination to decrypt the data
	with open(d_key, "rb") as key_file:
                private_key = serialization.load_pem_private_key(key_file.read(),password=None,backend=default_backend())
#Decrypting the Symmetric Key		
	plaintext = private_key.decrypt(signature3[0],padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

	decryptor = Cipher(algorithms.AES(plaintext), modes.GCM(signature3[2], signature3[4]), backend=default_backend()).decryptor()

	decryptor.authenticate_additional_data(signature3[5])

#Decrypting and writing the data
        coded = decryptor.update(signature3[3]) + decryptor.finalize()
	with open(plain_text, 'w') as df:
        	for items in coded:
                	df.write(items)
#Verifying the integrity of Data
        verifier = public_key.verifier(signature3[1], padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
	verifier.update(coded)

if __name__ == "__main__":
	main(sys.argv[1:])
