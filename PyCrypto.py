#!Env/Crypto/bin/python 2.7 
#-*coding: utf-8 -*-
"""
author:james.bondu
python linear-regression predicter
python-version - 2.7
"""

from Crypto.PublicKey import RSA
import os, sys, random, struct
import hashlib
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

def RsaKeyGenerator(code):
    key = RSA.generate(2048)
    encrypted_key = key.exportKey(passphrase = code, pkcs=8,
                              protection="scryptAndAES128-CBC")

    with open('my_private_rsa_key.bin', 'wb') as f:
        f.write(encrypted_key)
    print key.publickey().exportKey()
    with open('rsa_public.pem', 'wb') as f:
        f.write(key.publickey().exportKey())

        
def RsaEncrypt(in_filename, out_filename=None):
    if not out_filename:
        out_filename = in_filename + '.enc'
    print('Encrypting... \n file='+in_filename)

    filesize = os.path.getsize(in_filename)
#    recipient_key= RSA.importKey(open('rsa_public.pem').read())
#    cipher_rsa= PKCS1_OAEP.new(recipient_key)
    with open(out_filename, 'wb') as out_file:
        recipient_key = RSA.import_key(open('rsa_public.pem').read())
        f=open(in_filename,'r')
        message = f.read()
        print message
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        out_file.write(cipher_rsa.encrypt(message))
    

def RsaDecrypt(in_filename, out_filename=None):
    if not out_filename:
        #out_filename = os.path.splitext(in_filename)
        out_filename = 'out.txt'

    print('Decrypting... \nfile ='+in_filename)
    code = raw_input("Give code :")
    private_key = RSA.import_key(open('my_private_rsa_key.bin').read(),passphrase= code)
    f=open(in_filename,'r')
    message = f.read()
    print message
    cipher_rsa = PKCS1_OAEP.new(private_key)
    data =  cipher_rsa.decrypt(message)
    print data


def AesEncryptFile(key, in_filename, out_filename=None, chunksize=64*1024):
    """ Encrypts a file using AES (CBC mode) with the
        given key.

        key:
            The encryption key - a string that must be
            either 16, 24 or 32 bytes long. Longer keys
            are more secure.

        in_filename:
            Name of the input file

        out_filename:
            If None, '<in_filename>.enc' will be used.

        chunksize:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunksize must be divisible by 16.
    """
    if not out_filename:
        out_filename = in_filename + '.AESenc'
    
    key = hashlib.sha256(password).digest()
    print('Encrypting... \nfile ='+in_filename+'\nkey ='+ password +'\nhashed_key = '+ key)
    
    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))



def AesDecryptFile(password, in_filename, out_filename=None, chunksize=24*1024):
    """ Decrypts a file using AES (CBC mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: out_filename, if not supplied
        will be in_filename without its last extension
        (i.e. if in_filename is 'aaa.zip.enc' then
        out_filename will be 'aaa.zip')
    """
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]+'(1)'
    key = hashlib.sha256(password).digest()

    print('Decrypting... \nfile ='+in_filename+'\nkey ='+ password+'\nhashed_key = '+ key)
    
    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)

    
if __name__ == '__main__':
    algos = sys.argv[1]
    option = sys.argv[2]
    if (algos == 'RSA'):
        if (option == 'encrypt'):
            #print ("Enter RSA public password")
            code = raw_input("Enter RSA secret code : ")
            print code
            RsaKeyGenerator(code)
            #RsaKeyGenerator()
            Rsa_ip = raw_input("Encrypt Message or File : ")
            if (Rsa_ip == 'Message'):
                message = raw_input("Print message here :")
                with open('message.txt','wb') as f:
                    f.write(message)
                file = 'message.txt'
                RsaEncrypt(file)

            if (Rsa_ip == 'File'):
                print ("RSA File size must not exceed 216bytes to encrypt")    
                file = raw_input("Print file name")
                RsaEncrypt(file)
        if(option == 'decrypt'):
            dersa_ip = raw_input("Decrypt Message or File :" )
            if (dersa_ip == "Message"):
                file = 'message.txt.enc'
                RsaDecrypt(file)
            else:
                file = raw_input("Print Filename :")
                RsaDecrypt(file)
                
    if(algos == 'AES'):
        password = raw_input("Provide password :")
        if(option == 'encrypt'):
            filename = raw_input("Give Encryption Filename : ")
            AesEncryptFile(password,filename)
        if(option == 'decrypt'):
            filename = raw_input("Give Decryption Filename : ")
            AesDecryptFile(password,filename)        

