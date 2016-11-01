For server side, run “python s.py” on the command line.
For client side, run “python c.py” on the command line.

• Server starts and creates RSA keys [3].
• Then sends the public key to the client using cPickle which is used to serialize and de-serialize
the key [4].
• Client generates a secret key, an IV and a salt, and encrypts using the public key and sends them
to the server using cPickle.
• Server decrypts the message using its private key and gets the secret key of the client.
• Now two keys were generated using PBKDF2 [2] library, following the code from [1]. This can
also be done just using hash functions, which is used in this project, as while importing
PBKDF2 from Crypto.Protocol.KDF on the CSE machine, the following error occurred:
“ImportError: No module named KDF”
A point should be noted here: for verification purpose from the client side, the two keys were
also generated on the client side.
• Now these two keys can be used to verify MACs of both plain texts and cipher texts received
from the client as was already done on project 1.
•
Notes from project 1:
This implementation is inspired by [6], where HMAC has been used. An HMAC is a
cryptographic hash that uses a key to sign a message. The receiver verifies the hash by
recomputing it using the same key [7]. So in this code the same key is hard-coded on the
variable “accesskey” and used for both signing and authenticating.

References:
[1] https://bitbucket.org/brendanlong/python-
encryption/raw/1737e959fa307d84a5dcf96c4139b1d91a08b2e9/encryption.py
[2] https://pypi.python.org/pypi/pbkdf2
[3] https://gist.github.com/lkdocs/6519378
[4] https://docs.python.org/2/library/pickle.html
[5] https://docs.python.org/3/library/hmac.html#module-hmac
[6] https://gist.github.com/binaryatrocity/7079332cab038da1394d
[7] https://golang.org/pkg/crypto/hmac/
