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
    host = 'localhost'
    port = 1212

    #create an INET, STREAMing socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.connect((host,port))
    if (server.recv(1024) == "KeyGenerated"):
        print "Step 1: Key pair generated on the server. Ready to proceed."
    server.sendall("GetPublicKey")
    spk = server.recv(1024)
    server_pub_key=cPickle.loads(spk)
    print "Step 2: Client has the Public Key"
    
    server.sendall("GetSupportedSchemes")
    scheme = server.recv(1024)
    #print "Supported Scheme: " + scheme
    
    server.sendall("GetSupportedMAC")
    mac = server.recv(1024)
    #print "Supported MAC: " + mac
    
    #sk = "KeyForEncryption"
    sk = Random.new().read(16)
    IV = Random.new().read(AES.block_size)
    salt = Random.new().read(16)
    
    server.sendall("SendSecretKey")
    enc_data = server_pub_key.encrypt(sk + ":::" + IV + ":::" + salt, 32)
    
    (secretKey, accesskey, salt, interations) = make_keys(sk,  salt)
    #print secretKey
    #print accesskey
    
    if (server.recv(1024) == "OK"):
        datagram = cPickle.dumps(enc_data)
        server.sendall(datagram)
        print "Step 3: Client has encrypted the secret key and has sent it to the server"
        if (server.recv(1024) == "OK"):
            print "Step 4: Server has the secret key"
        
    server.sendall("GenerateKeys")
    if (server.recv(1024) == "OK"):
        print "Step 5: Key generated on the server"
    
    print "Step 6: Steps from the project 1"
    print "--------------------------------------------"
    print "CORRECT MAC:"
    print "--------------------------------------------"
    server.sendall("TOKEN")
    if (server.recv(1024) == "OK"):
        token = create_token(accesskey,  "Plain_text_to_check_encryption.")
        #paddedToken = padPlainText(token)
        server.sendall(token)
        print "1a. MAC and plaintext sent to server: " + token
        etoken = server.recv(1024)
        print "MAC and ciphertext received from server: " + etoken
        lead, ciphertext, signature = etoken.split(":::")
        if lead=="0":
            print "1b. MAC VERIFICATION FAILED ON THE SERVER"
            print "MAC Calculated by the server: "+ signature
        else:
            print "1b. MAC was verified by the server and encrypted text and it's MAC was received"
            
            print "(For verification) The plaintext of the ciphertext is: " + decrypt(ciphertext,  secretKey,  IV)
            authentication = authenticate_signed_token(accesskey,  etoken)
            if authentication:
                print "1c. MAC from the server has been verified"
            else:
                print "1c. MAC VERIFICATION FAILED"
        print "--------------------------------------------"
    
    print "CORRECT MAC:"
    print "--------------------------------------------"
    server.sendall("ETOKEN")
    if (server.recv(1024) == "OK"):
        eText = encrypt(padPlainText('Plain_text_to_check_decryption.'),  secretKey,  IV)
        token = create_token(accesskey,  eText)
        
        server.sendall(token)
        print "2a. MAC and ciphertext sent to server: " + token
        etoken = server.recv(1024)
        lead, ciphertext, signature = etoken.split(":::")
        if lead=="0":
            print "2b. MAC VERIFICATION FAILED ON THE SERVER"
            print "MAC Calculated by the server: "+ signature
        else:
            print "2b. MAC was verified by the server and decrypted text and it's MAC was received"
            print "MAC and plaintext received from server: " + etoken
            authentication = authenticate_signed_token(accesskey,  etoken)
            if authentication:
                print "2c. MAC of the plaintext received from the server has been verified"
            else:
                print "2c. MAC VERIFICATION FAILED"
        print "--------------------------------------------"
    
    print "INCORRECT MAC:"
    print "--------------------------------------------"
    server.sendall("TOKEN")
    if (server.recv(1024) == "OK"):
        token = create_token(accesskey,  "Plain_text_to_check_encryption.")
        #Modify the MAC to send a wrong MAC to the server
        token = token + "Extend"
        server.sendall(token)
        print "1a. MAC and plaintext sent to server: " + token
        etoken = server.recv(1024)
        lead, ciphertext, signature = etoken.split(":::")
        if lead=="0":
            print "1b. MAC VERIFICATION FAILED IN THE SERVER"
            print "MAC Calculated by the server: "+ signature
        else:
            print "1b. MAC was verified by the server and encrypted text and it's MAC was received"
            print "MAC and ciphertext received from server: " + etoken
            print "(For verification) The plaintext of the ciphertext is: " + decrypt(ciphertext,  secretKey,  IV)
            authentication = authenticate_signed_token(accesskey,  etoken)
            if authentication:
                print "1c. MAC from the server has been verified"
            else:
                print "1c. MAC VERIFICATION FAILED"
        print "--------------------------------------------"
    
    print "INCORRECT MAC:"
    print "--------------------------------------------"
    server.sendall("ETOKEN")
    if (server.recv(1024) == "OK"):
        eText = encrypt(padPlainText('Plain_text_to_check_decryption.'),  secretKey,  IV)
        token = create_token(accesskey,  eText)
        #Modify the MAC to send a wrong MAC to the server
        token = token + "Extend"
        server.sendall(token)
        print "2a. MAC and ciphertext sent to server: " + token
        etoken = server.recv(1024)
        lead, ciphertext, signature = etoken.split(":::")
        if lead=="0":
            print "2b. MAC VERIFICATION FAILED IN THE SERVER"
            print "MAC Calculated by the server: "+ signature
        else:
            print "2b. MAC was verified by the server and decrypted text and it's MAC was received"
            print "MAC and plaintext received from server: " + etoken
            authentication = authenticate_signed_token(accesskey,  etoken)
            if authentication:
                print "2c. MAC of the plaintext received from the server has been verified"
            else:
                print "2c. MAC VERIFICATION FAILED"
        print "--------------------------------------------"
    
    server.sendall("exit")
    print "Exit Command sent"
    server.close()

main()
