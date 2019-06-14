from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random
import hashlib
import uuid

lorem_ipsum = '''Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.'''

def encrypt_key(string):
	aes_key = Random.new().read(32)
	iv = Random.new().read(AES.block_size)
	cipher = AES.new(aes_key, AES.MODE_CFB, iv)
	package = iv + cipher.encrypt(string.encode('utf-8'))
	
	random_generator = Random.new().read
	rsakey = RSA.generate(1024, random_generator)
	encryptor = rsakey.publickey()
	decryptor = rsakey.exportKey()
	#rsa_cipher = PKCS1_OAEP.new(encryptor)
	#encrypted_aes_key = rsa_cipher.encrypt(aes_key)
	encrypted_aes_key = encryptor.encrypt(aes_key,32)
	
	guid = str(uuid.uuid1())
	
	key_hash = hashlib.sha256()
	key_hash.update(package)
	
	return {'package':package,'aes_key':encrypted_aes_key,'decryptor':decryptor,'guid':guid,'hash':key_hash.hexdigest()}

#key_struct = 
#{
#	package: the encrypted text from the aes encryption
#	aes_key: the AES key to decrypt the package.
#	public_key: public RSA key to decrypt aes_key
#	guid: a unique identifier for this key
#	hash: hash of package for verification
#}

def decrypt_key(package,encrypted_aes_key,public_key_string):
	public_key = RSA.importKey(public_key_string)
	aes_key = public_key.decrypt(encrypted_aes_key)
	
	iv = package[:AES.block_size]
	cipher = AES.new(aes_key,AES.MODE_CFB, iv)
	return cipher.decrypt(package)[AES.block_size:]

key = encrypt_key(lorem_ipsum)
print(decrypt_key(key['package'],key['aes_key'],key['decryptor']))
