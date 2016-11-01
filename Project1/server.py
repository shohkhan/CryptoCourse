from Crypto.Cipher import AES
import socket, sys
#import base64

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
    keepconnection = 1
    
    #Start Server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host,port))
    server.listen(5)

    while keepconnection == 1:
        #Wait for connection from client
        (client, address) = server.accept()
        supportedSchemes= "AES"
        supportedMac = "HMAC"

        #Send back the supported schemes
        client.send("Available encryption systems in server: " + supportedSchemes +"\nAvailable MAC algorithm in server:" + supportedMac)

        #Scheme choosen by client
        scheme = client.recv(1024)
        if scheme == "AES":
            client.send("OK")
            IV = client.recv(16)
            print("Initial Vector: \""+IV+"\"")
            secretKey = client.recv(16)
            print("Secret Key: \""+secretKey+"\"")
            accesskey = 'KeyForHmac'
            aes = AES.new(secretKey, AES.MODE_CBC, IV)
            #Server recevies the message for requested function from client

            #Step 1
            token1 = client.recv(1024)
            authentication = authenticate_signed_token(accesskey,  token1)
            if (authentication):
                print "MAC VERIFIED"
                lead, tokenText, signature = token1.split(":")
                modifiedText = aes.encrypt(padPlainText(tokenText))
                etoken1 = create_token(accesskey,  modifiedText)
                client.sendall (etoken1)
            else:
                print "MAC VERIFICATION FAILED"
                lead, tokenText, signature = token1.split(":")
                calculated_hmac = create_signature(accesskey, tokenText)
                client.sendall ("0:0:" + calculated_hmac)
            
            #Step 2
            token2 = client.recv(1024)
            lead, tokenText, signature = token2.split(":")
            authentication = authenticate_signed_token(accesskey,  token2)
            if (authentication):
                print "MAC VERIFIED"
                lead, tokenText, signature = token2.split(":")
                newText = aes.decrypt(tokenText)
                modifiedText = unpadPlainText(newText)
                etoken2 = create_token(accesskey,  modifiedText)
                client.sendall (etoken2)
            else:
                print "MAC VERIFICATION FAILED"
                lead, tokenText, signature = token2.split(":")
                calculated_hmac = create_signature(accesskey, tokenText)
                client.sendall ("0:0:" + calculated_hmac)

        else:
            client.send("The scheme '" + scheme +"' is not valid")
        keepconnection = 0

main()
