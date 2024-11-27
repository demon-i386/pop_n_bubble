import time
import base64
from hashlib import md5, pbkdf2_hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# IV extraido do decrypt do payload - usado para criptografar novo payload
payload_iv = ""

# Chave extraida do decrypt do payload - usado para criptografar novo payload
payload_key = ""

# appname do header X-Bubble-Appname ou debugging do JS.
appname = ""

# payload em texto plano a ser criptografado
payload_new = b''


def derive_key_and_iv(appname, payload_key):

    # Derivando a chave
    key = f"{appname}{payload_key}".encode('utf-8')
    derived_key = pbkdf2_hmac('md5', key, appname.encode('utf-8'), 7, dklen=32)

    # Derivando o IV
    derived_iv = pbkdf2_hmac('md5', payload_iv.encode('utf-8'), appname.encode('utf-8'), 7, dklen=16)

    return derived_key, derived_iv

def encrypt_payload(data, appname):
    # Derivar chave e IV
    derived_key, derived_iv = derive_key_and_iv(appname, payload_key)

    # Criar o objeto Cipher
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(derived_iv))
    encryptor = cipher.encryptor()

    # Padding do dado
    padded_data = pad_data(data)
    # Encriptar os dados
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Retornar o texto cifrado em base64
    return base64.b64encode(ciphertext).decode('utf-8')

def pad_data(data):
    # PKCS7 Padding
    pad_length = 16 - (len(data) % 16)
    return data + bytes([pad_length] * pad_length)

encrypted_data = encrypt_payload(payload_new, appname)

print(f'Encrypted payload: {encrypted_data}')
