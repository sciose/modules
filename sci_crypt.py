
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import math

def rsa_encrypt(public_key,data):
  '''Encrypt data and return base64 encoded blob'''
  encrypted = []

  key = RSA.importKey(public_key)
  cypher = PKCS1_OAEP.new(key)

  #size of block key_size in bytes - 42 for OAEP padding
  block_size = int((key.size()+1)/8-84)
  number_blocks = math.ceil(len(data)/block_size)

  for i in range(number_blocks):
    block_start = i*block_size
    block_end = block_start+block_size
    block = data[block_start:block_end]

    encrypted.append(cypher.encrypt(block.encode(encoding)))

  encrypted = b''.join(encrypted)

  return base64.b64encode(encrypted)


def rsa_decrypt(private_key,data, encoding = None):
    '''Decrypt data and return string decoded to supplied encoding'''
    decrypted = []
    key = RSA.importKey(private_key)
    cipher = PKCS1_OAEP.new(key)

    data = base64.b64decode(data)

    block_size = int((key.size()+1)/8)
    number_blocks = math.ceil(len(data)/block_size)

    for i in range(number_blocks):
      block_start = i*block_size
      block_end = block_start+block_size
      block = data[block_start:block_end]

      decrypted.append(cipher.decrypt(block))

     if encoding:
         return decrypted[0].decode(encoding)
     else:
         return decrypted[0]

'''
pub_key = 'key'
priv_key = 'key'

#encrypt input file to output file
with open('input_file') as f_in:
  with open('output_file', 'wb') as f_out:
    data = f_in.read()
    encrypted = rsa_encrypt(pub_key,data)
    f_out.write(encrypted)

#decrypt and display plain-text
with open('output_file', 'rb') as f_in:
    decrypted = rsa_decrypt(priv_key,f_in.read(),'utf-8')
    print(decrypted)
'''
