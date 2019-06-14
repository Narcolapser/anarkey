#! /usr/bin/python
#crypto bits
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random
import hashlib
import uuid
import base64
import json

#utility bits
from os import listdir
from os.path import isfile, join

key_chain_template = """{{
	"type" : "Key Chain",
	"user" : "{user}",
	"public key" : "{public_key}",
	"public key validator" : "{validator}",
	"key chain" : "{keychain}",
	"encrypted aes key" : "{aes}",
	"inbox" : []
}}"""

#list user keychains
def list_keychains():
	keychains_candidates = [f for f in listdir('./') if '.anrkc' in f]
	
	#no key chains found. exiting.
	if len(keychains_candidates) == 0:
		return []
	
	keychains = [keychain for keychain in keychains_candidates if validate_key_chain(keychain)]
	print(keychains)

def validate_key_chain(path):
	kc_file = open(path,'r').read()
	
	try:
		kc_json = json.loads(kc_file)
	except:
		#doesn't load like a json file, not an anarkey key chain.
		return False
	
	try:
		if kc_json['type'] != 'Key Chain':
			#file does not call itself a key chain.
			return False
	except:
		#doesn't have 'type' value.
		return False

	parts = ["type","user","public key","public key validator","key chain","encrypted aes key","inbox"]
	for part in parts:
		if part not in kc_json.keys():
			#missing part of the keychain file, not a keychian.
			return False
	
#	#if it passes all tests, it's a key chain.
	return True

def new_keychain(user,greeting):
	parameters = {}
	
	parameters['user'] = user
	
	aes_key = Random.new().read(32)
	iv = Random.new().read(AES.block_size)
	cipher = AES.new(aes_key, AES.MODE_CFB, iv)
	parameters['keychain'] =  base64.b64encode(iv + cipher.encrypt(b'[]'))
	
	random_generator = Random.new().read
	rsakey = RSA.generate(2048, random_generator)
	parameters['public_key'] = rsakey.publickey().exportKey().replace('\n','')
	private_key = rsakey.exportKey()
	
	parameters['aes'] = base64.b64encode(rsakey.publickey().encrypt(aes_key,32)[0])

	#this is encoded with the private key to validate the public key.
	parameters['validator'] = base64.b64encode(rsakey.encrypt(greeting,256)[0])
	
	open('{}.anrkc'.format(user),'w').write(key_chain_template.format(**parameters))
	return private_key

list_keychains()

#print(new_keychain('alice','this is alice\'s key chain!'))
