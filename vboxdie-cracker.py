import base64, sys, struct, binascii, os, time, hashlib
import xml.etree.ElementTree as ET
import OpenSSL
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

"""
	Process encoded KeyStore and verify some of their values
	Returns an array with the values defined in the format
"""
def process_keystore(encoded_keystore): 
	keystore = base64.b64decode(encoded_keystore)

	keystore_struct = ( 
			'header',						# 4 bytes keystore header
            'version',						# 2 bytes version
            'algorithm',					# 32 bytes algorithm name
            'kdf',							# 32 bytes key derivation function name
            'generic_key_length',			# 4 bytes generic length
				            					# first PBKDF2 output length
				                                # second PBKDF2 input length
				                                # EVP decrypted string length
            'final_hash',					# 32 bytes final hash, comparison done here
            'pbkdf2_2_key_length',			# 4 bytes second PBKDF2 output length
            'pbkdf2_2_salt',				# 32 bytes second PBKDF2 salt
            'pbkdf2_2_iterations',			# 4 bytes second PBKDF2 iterations
            'pbkdf2_1_salt',				# 32 bytes first PBKDF2 salt
            'pbkdf2_1_iterations',			# 4 bytes first PBKDF2 iterations
            'evp_decrypt_input_length',		# 4 bytes EVP input length
            'pbkdf2_2_encrypted_password'	# 64 bytes encrypted password for PBKDF2 2

		)

	keystore_format = ('=IH32s32sI32sI32sI32sII64s')


	keystore = struct.unpack(keystore_format, keystore)
	keystore = dict(zip(keystore_struct,keystore))
	#print(keystore)

	# Check keystone header
	if keystore['header'] != 0x454E4353: 
		return False

	# Check method and hash constants
	if not get_openssl_method(keystore): 
		return False

	if not get_hash_algorithm(keystore): 
		return False

	return keystore


"""
	Makes a bruteforce to find the final hash contained in the KeyStore
	Returns the plaintext password used to encrypt de disk of the virtual machine
"""
def crack_keystore(keystore, wordlist): 
	# Open wordlist file
	with open(wordlist, "r") as f:

		# Get hash and method from keystore
		hash_ = get_hash_algorithm(keystore)
		method = get_openssl_method(keystore)

		# Read each line of the file, it is the user password
		for user_password in f: 
			user_password = user_password.strip()

			# First call to PBKDF2
			EVP_password = hashlib.pbkdf2_hmac(hash_, user_password.encode(), keystore['pbkdf2_1_salt'], keystore['pbkdf2_1_iterations'], keystore['generic_key_length'])
			# Here, the password used for the second call to PBKDF2 is decrypted
			backend = default_backend()
			cipher = Cipher(algorithms.AES(
					EVP_password
				), modes.XTS(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'), 
				backend=backend)
			decryptor = cipher.decryptor()
			decrypted_password = decryptor.update(keystore['pbkdf2_2_encrypted_password'][0:keystore['evp_decrypt_input_length']]) + decryptor.finalize()

			# Final hash is computed
			final_hash = hashlib.pbkdf2_hmac(hash_, decrypted_password, keystore['pbkdf2_2_salt'], keystore['pbkdf2_2_iterations'], keystore['pbkdf2_2_key_length'])

			# If the computed hash is equal to the stored hash, then we have got the right user password
			if final_hash == keystore['final_hash']:
				return user_password

		return False

"""
	Prints the values of the decoded KeyStore
"""
def print_keystore(keystore): 
	print('\t%-30s%s' % ('Header', '%s%s' % (hex(keystore['header'])[2:]," (SCNE)")))
	print('\t%-30s%s' % ('Version', str(keystore['version'])))
	print('\t%-30s%s' % ('Algorithm', keystore['algorithm'].strip(b'\x00').decode()))
	print('\t%-30s%s' % ('KDF', keystore['kdf'].strip(b'\x00').decode()))
	print('\t%-30s%s' % ('Key length', keystore['generic_key_length']))
	print('\t%-30s%s' % ('Final hash', binascii.hexlify(keystore['final_hash']).decode()))
	print('\t%-30s%s' % ('PBKDF2 2 Key Length', keystore['pbkdf2_2_key_length']))
	print('\t%-30s%s' % ('PBKDF2 2 Salt', binascii.hexlify(keystore['pbkdf2_2_salt']).decode()))
	print('\t%-30s%s' % ('PBKDF2 2 Iterations', keystore['pbkdf2_2_iterations']))
	print('\t%-30s%s' % ('PBKDF2 1 Salt', binascii.hexlify(keystore['pbkdf2_1_salt']).decode()))
	print('\t%-30s%s' % ('PBKDF2 1 Iterations', keystore['pbkdf2_1_iterations']))
	print('\t%-30s%s' % ('EVP buffer length', keystore['evp_decrypt_input_length']))

	# Print the encrypted password in two lines
	encrypted_length = len(keystore['pbkdf2_2_encrypted_password'])
	print("\t%-30s%s" % ('PBKDF2 2 encrypted password',binascii.hexlify(keystore['pbkdf2_2_encrypted_password'][0:encrypted_length//2]).decode()))
	print("\t%-30s%s" % ('',binascii.hexlify(keystore['pbkdf2_2_encrypted_password'][encrypted_length//2:]).decode()))



"""
	Returns the hash to be used by PBKDF2
"""
def get_openssl_method(keystore): 
	# EVP algorithms supported by VirtualBox
	if keystore['algorithm'].strip(b'\x00') == b'AES-XTS128-PLAIN64': 
		return 'aes-128-xts'
	elif keystore['algorithm'].strip(b'\x00') == b'AES-XTS256-PLAIN64': 
		return 'aes-256-xts'
	else: 
		return False


"""
	Returns the hash to be used by PBKDF2
"""
def get_hash_algorithm(keystore): 
	# Hash algorithms supported by VirtualBox
	if keystore['kdf'].strip(b'\x00') == b'PBKDF2-SHA1': 
		return 'sha1'
	elif keystore['kdf'].strip(b'\x00') == b'PBKDF2-SHA256': 
		return 'sha256'
	elif keystore['kdf'].strip(b'\x00') == b'PBKDF2-SHA512': 
		return 'sha512'
	else: 
		return False


"""
	Process the VirtualBox configuration file
	Shows if any of the disks defined in the configuration are encrypted
"""
def process_configuration_file(path, wordlist): 
	print("[+] Reading data from: %s" % (path))

	# Load file
	try: 
		tree = ET.parse(path)
		root = tree.getroot()
	except: 
		print("[-] XML parsing failed for: %s" % path)
		return

	# Register VBOX namespace to avoid issues
	ns = {'vbox': 'http://www.virtualbox.org/',}

	# Get the list of all the hard disks available on the config file
	hardDisks =  root.findall(".//vbox:HardDisks",ns)

	# Iterate over each disk
	for hardDisk in hardDisks[0]: 
		# Get disk location
		location = hardDisk.get("location")
		print("-"*64)
		print("[+] Checking hard disk encryption for: %s" % location)

		keyID = None; encoded_keystore = None
		# Check for encryption disk properties
		properties = hardDisk.findall("vbox:Property",ns)
		for prop in properties: 
			name = prop.get("name")
			value = prop.get("value")

			if name == "CRYPT/KeyId": 
				keyID = value
			elif name == "CRYPT/KeyStore": 
				encoded_keystore = value

		# Keystore found on disk!
		if not encoded_keystore: 
			print("[-] Hard disk is not encrypted")
			continue

		print("[+] Hard disk is encrypted")
		print("[+] KeyStore encoded string: ")
		print("%s" % (encoded_keystore.replace("\r\n","\n")))

		# Process the KeyStore
		keystore = process_keystore(encoded_keystore)
		if keystore == False: 
			print("[-] Invalid KeyStore found")
			continue

		# Print the KeyStore
		print("[+] KeyStore contents: ")
		print_keystore(keystore)

		# Check if wordlist parameter was provided and if it exists
		if wordlist == None or not os.path.isfile(wordlist): 
			print("[-] Wordlist not provided or not found, cracking halted")
			continue

		# Start cracking
		start = time.time()
		result = crack_keystore(keystore, wordlist)
		end = time.time()

		# Cracking process end, let see the time and the result
		print("[+] Cracking finished, measured time: %.5f seconds" % (end-start))
		if result != False: 
			print("[!] KeyStore password found: %s" % (result))
		else: 
			print("[-] KeyStore password not found")


def main(): 
	print("Welcome to VirtualBox Disk Image Encryption cracker, Python Version")
	try: 
		keystore = sys.argv[1]
	except: 
		print("Usage: python vboxdie-cracker.py disk_image.vbox wordlist")
		return
	if len(sys.argv) == 2: 
		wordlist = None
	else: 
		wordlist = sys.argv[2]

	process_configuration_file(keystore,wordlist)

if __name__ == "__main__": 
	main()