from Crypto.Cipher import AES
from Crypto import Random
import socket, sys
import socket
from base64 import b64encode
from Crypto.Hash import SHA256, HMAC

def create_signature(secret_key, string_to_sign):
    #Create the signed message from api_key and string_to_sign
    #string_to_sign = string.encode('utf-8')
    hmac = HMAC.new(secret_key, string_to_sign, SHA256)
    return b64encode(hmac.hexdigest())

def create_token(access_key,  string_to_sign):
    #Create the full token (CONE:access_key:signed_string)
    user_secret_key = access_key # Should be looked up based on access_key
    hmac = create_signature(access_key, string_to_sign)
    signature = "HMAC" + ":" + string_to_sign + ":" + hmac
    return signature

def authenticate_signed_token(access_key,  auth_token):
    #Take token, recreate signature, auth if a match
    lead, string_to_check, signature = auth_token.split(":")
    if lead.upper() == "HMAC":
        our_token = create_token(access_key,  string_to_check).split(":", 2)[-1]
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

    #Available schemes on server
    suppSchemes = server.recv(1024)
    print("Received: "+suppSchemes)
    print "--------------------------------------------"
    #Client choses a scheme
    chosenScheme ="AES"
    if(chosenScheme == "AES"):
        server.send(chosenScheme)
        proceed = server.recv(1024)
        if (proceed == "OK"):
            accesskey = 'KeyForHmac'
            #IV and secretKey
            IV = "IVvalueforAES123"
            secretKey = "KeyForEncryption"
            server.send(IV)
            server.send(secretKey)
            aes = AES.new(secretKey, AES.MODE_CBC, IV)
            
            token = create_token(accesskey,  "Plain_text_to_check_encryption.")
            #Modify the MAC to send a wrong MAC to the server
            server.sendall(token + "Extend")
            print "1a. MAC and plaintext sent to server: " + token + "Extend"
            etoken = server.recv(1024)
            lead, ciphertext, signature = etoken.split(":")
            if lead=="0":
                print "1b. MAC VERIFICATION FAILED IN THE SERVER"
                print "MAC Calculated by the server: "+ signature
            else:
                print "1b. MAC was verified by the server and encrypted text and it's MAC was received"
                print "MAC and ciphertext received from server: " + etoken
                print "(For verification) The plaintext of the ciphertext is: " + aes.decrypt(ciphertext)
                authentication = authenticate_signed_token(accesskey,  etoken)
                if authentication:
                    print "1c. MAC from the server has been verified"
                else:
                    print "1c. MAC VERIFICATION FAILED"
                print "--------------------------------------------\n\n"
            
            eText = aes.encrypt(padPlainText('Plain_text_to_check_decryption.'))
            token = create_token(accesskey,  eText)
            #Modify the MAC to send a wrong MAC to the server
            server.sendall(token + "Extend")
            print "2a. MAC and ciphertext sent to server: " + token + "Extend"
            etoken = server.recv(1024)
            lead, ciphertext, signature = etoken.split(":")
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

    server.close()

main()
