from Crypto.Cipher import AES
import socket, sys
from base64 import b64encode
from Crypto.Hash import SHA256, HMAC
from Crypto.PublicKey import RSA
from Crypto import Random
#from Crypto.Protocol.KDF import PBKDF2
#from kdf import PBKDF2
import cPickle
import hashlib

def PBKDF2(password, salt, dkLen=16, count=1000, prf=None):
    password = tobytes(password)
    if prf is None:
        prf = lambda p,s: HMAC.new(p,s,SHA1).digest()
    key = b('')
    i = 1
    while len(key)<dkLen:
        U = previousU = prf(password,salt+struct.pack(">I", i))
        for j in xrange(count-1):
            previousU = t = prf(password,previousU)
            U = strxor(U,t)
        key += U
        i = i + 1
    return key[:dkLen]

def make_keys(password, salt, iterations=100000,  usePbkdf2 = 0):
    if usePbkdf2 == 1:
        # Generate a 32-byte (256-bit) key from the password
        prf = lambda p,s: HMAC.new(p, s, SHA256).digest()
        key = PBKDF2(password, salt, 32, iterations, prf)
        # Split the key into two 16-byte (128-bit) keys
        return key[:16], key[16:], salt, iterations
    else:
        hash_object = hashlib.sha256(password)
        hex_dig = hash_object.hexdigest()
        return hex_dig[:32], hex_dig[32:], salt, iterations
    
def make_hmac(message, key):
    h = HMAC.new(key)
    h.update(message)
    return h.hexdigest()

def encrypt(message, key,  iv):
    # The IV should always be random
    #iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(message)
    #return (ciphertext, iv)
    return ciphertext

def decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    msg = cipher.decrypt(ciphertext)
    return msg

def generate_RSA(bits=2048):
    #Generate an RSA keypair with an exponent of 65537 in PEM format param: bits 
    #The key length in bits Return private key and public key
    
    random_generator = Random.new().read
    new_key = RSA.generate(bits, random_generator) 
    #new_key = RSA.generate(bits, e=65537) 
    public_key = new_key.publickey().exportKey("PEM") 
    private_key = new_key.exportKey("PEM") 
    return private_key, public_key, new_key

def create_signature(secret_key, string_to_sign):
    #Create the signed message from api_key and string_to_sign
    #string_to_sign = string.encode('utf-8')
    hmac = HMAC.new(secret_key, string_to_sign, SHA256)
    return b64encode(hmac.hexdigest())
            
def create_token(access_key,  string_to_sign):
    #Create the full token (CONE:access_key:signed_string)
    user_secret_key = access_key # Should be looked up based on access_key
    hmac = create_signature(access_key, string_to_sign)
    signature = "HMAC" + ":::" + string_to_sign + ":::" + hmac
    return signature

def authenticate_signed_token(access_key,  auth_token):
    #Take token, recreate signature, auth if a match
    lead, string_to_check, signature = auth_token.split(":::")
    if lead.upper() == "HMAC":
        our_token = create_token(access_key,  string_to_check).split(":::", 2)[-1]
    return True if signature == our_token else False

def padPlainText(plainText):
    if(len(plainText)%16 != 0):
        plainTextforsend = plainText + ("#"*(16-len(plainText)%16))
        return plainTextforsend
    return plainText

def unpadPlainText(plainText):
    if(plainText.find("#") != -1):
        plainText = plainText[:(plainText.index('#'))]
    return plainText

def main():
    (priv_key,  pub_key, key) = generate_RSA();
    IV = ""
    salt = ""
    keyFromClient =""
    secretKey = ""
    accesskey = ""
    host = 'localhost'
    port = 1212
    keepconnection = 1

    #Start Server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host,port))
    server.listen(5)
    #Wait for connection from client
    (client, address) = server.accept()
    client.sendall("KeyGenerated")
    while keepconnection == 1:
        msg = client.recv(1024)
        print "Command: " + msg
        if (msg=="exit"):
            keepconnection = 0
        elif (msg == "GetPublicKey"): 
            to_send=cPickle.dumps(key.publickey())
            client.send(to_send)
        elif (msg == "GetSupportedSchemes"): 
            client.send("AES")
        elif (msg == "GetSupportedMAC"): 
            client.send("HMAC")
        elif(msg == "SendSecretKey"):
            client.sendall("OK")
            sk = client.recv(1024)
            k = cPickle.loads(sk)
            k = key.decrypt(k)
            keyFromClient, IV,  salt = k.split(":::")
            client.sendall("OK")
            #print "Salt: " + salt
            #print "IV: " + IV
            #print "Key: " + keyFromClient
        elif(msg == "GenerateKeys"):
            if (keyFromClient == "" or salt ==""):
                print "Key or salt not provided from client"
                keepconnection = 0
            else:
                (secretKey, accesskey, salt, interations) = make_keys(keyFromClient,  salt)
                #print "Secret Key: " + secretKey
                #print "Access Key: " + accesskey
                client.sendall("OK")
        elif msg == "TOKEN":
            client.sendall ("OK")
            token = client.recv(1024)
            authentication = authenticate_signed_token(accesskey,  token)
            if (authentication):
                print "MAC VERIFIED"
                lead, tokenText, signature = token.split(":::")
                modifiedText = encrypt(padPlainText(tokenText),  secretKey,  IV)
                etoken = create_token(accesskey,  modifiedText)
                client.sendall (etoken)
            else:
                print "MAC VERIFICATION FAILED"
                lead, tokenText, signature = token.split(":::")
                calculated_hmac = create_signature(accesskey, tokenText)
                client.sendall ("0:::0:::" + calculated_hmac)
        elif msg == "ETOKEN":
            client.sendall("OK")
            token = client.recv(1024)
            lead, tokenText, signature = token.split(":::")
            authentication = authenticate_signed_token(accesskey,  token)
            if (authentication):
                print "MAC VERIFIED"
                lead, tokenText, signature = token.split(":::")
                newText = decrypt(tokenText,  secretKey,  IV)
                modifiedText = unpadPlainText(newText)
                etoken = create_token(accesskey,  modifiedText)
                client.sendall (etoken)
            else:
                print "MAC VERIFICATION FAILED"
                lead, tokenText, signature = token.split(":::")
                calculated_hmac = create_signature(accesskey, tokenText)
                client.sendall ("0:::0:::" + calculated_hmac)
        else:
            print "Command Not Found"
            keepconnection = 0
main()
