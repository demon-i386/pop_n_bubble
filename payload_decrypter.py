from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os
from hashlib import md5, pbkdf2_hmac


# ciphertext - payload.
ciphertext_z = ''

# ciphertext - key.
ciphertext_y = ''

# ciphertext - IV.
ciphertext_x = ''

# appname do header X-Bubble-Appname ou debugging do JS.
appname = ""

# IVs fixos utilizados pelo Bubble.io -> obtidos através de debugging no JS da aplicação.
fixed_iv_for_ciphertext_y = 'po9'
fixed_iv_for_ciphertext_x = 'fl1'

# funcao para automatizar decrypt de valores com chaves/IVs fixos
def decode_with_fixed_key_and_iv(appname, ciphertext_b64, custom_iv):
    ciphertext = base64.b64decode(ciphertext_b64)

    derived_iv_2 = pbkdf2_hmac('md5', custom_iv.encode('utf-8'), appname.encode('utf-8'), 7, dklen=16)
    derived_key_2 = pbkdf2_hmac('md5', appname.encode('utf-8'), appname.encode('utf-8'), 7, dklen=32)

    cipher = Cipher(algorithms.AES(derived_key_2), modes.CBC(derived_iv_2), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    return decrypted_padded

decoded_y = decode_with_fixed_key_and_iv(appname, ciphertext_y, fixed_iv_for_ciphertext_y).decode('utf-8').replace('_1', '') 
decoded_x = decode_with_fixed_key_and_iv(appname, ciphertext_x, fixed_iv_for_ciphertext_x).replace(b'\x0e', b'').replace(b'\r', b'').replace(b'\x0f',b'')


def derive_key_iv(appname, iv, key):
    # Derivando a chave
    derived_key = pbkdf2_hmac('md5', key.encode('utf-8'), appname.encode('utf-8'), 7, dklen=32)
    # Derivando o IV
    derived_iv = pbkdf2_hmac('md5', iv, appname.encode('utf-8'), 7, dklen=16)
    return derived_key, derived_iv


def derive_key_iv(appname, iv, key):
    print(key)
    derived_key = pbkdf2_hmac('md5', key.encode('utf-8'), appname.encode('utf-8'), 7, dklen=32)

    print(iv)
    derived_iv = pbkdf2_hmac('md5', iv, appname.encode('utf-8'), 7, dklen=16)

    return derived_key, derived_iv


def decrypt_final(derived_key, derived_iv):
    ciphertext = base64.b64decode(ciphertext_b64)

    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(derived_iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Remover padding (PKCS7)
    pad_length = decrypted_padded[-1]
    decrypted = decrypted_padded[:-pad_length]
    return decrypted


def derive_key_and_iv(timestamp, iv):
    key = f"{appname}{timestamp}".encode('utf-8').replace(b'\x01', b'')
    print(f"CREATED FINAL KEY (APPNAME + TIMESTAMP): {key}")

    derived_key = pbkdf2_hmac('md5', key, appname.encode('utf-8'), 7, dklen=32)
    derived_iv = pbkdf2_hmac('md5', iv, appname.encode('utf-8'), 7, dklen=16)

    return derived_key, derived_iv

def unpad_data(padded_data):
    # Remover PKCS7 Padding
    pad_length = padded_data[-1]
    return padded_data[:-pad_length]

def decrypt_payload(encrypted_data_b64, appname, timestamp, iv):

    # Decodificar o texto cifrado de Base64
    payload_elastic = base64.b64decode(encrypted_data_b64)

    # Derivar chave e IV
    derived_key, derived_iv = derive_key_and_iv(timestamp, iv)

    # Criar o objeto Cipher
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(derived_iv))
    decryptor = cipher.decryptor()

    # Decriptar os dados
    decrypted_padded = decryptor.update(payload_elastic) + decryptor.finalize()

    # Remover padding
    decrypted_data = unpad_data(decrypted_padded)

    return decrypted_data


print("")
print(f'decoded_y (TIMESTAMP): {decoded_y}')
print(f'decoded_x        (IV): {decoded_x}')

# decrypt do payload com chave e IV obtidas de decoded_y e decoded_x, respectivamente
# decrypt_data(ciphertext, appname, key, iv)
final_text = decrypt_payload(ciphertext_z, appname, decoded_y, decoded_x)

print(f'\nElasticsearch decoded payload: ')
print(final_text)
