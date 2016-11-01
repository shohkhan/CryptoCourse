a) For regular checking (MAC is correct) For server side, run “python server.py” on the command line. For client side, run “python client.py” on the command line. b) For incorrect MAC For server side, run “python server.py” on the command line. For client side, run “python client_wrong.py” on the command line.

This implementation is inspired by [1], where HMAC has been used. An HMAC is a cryptographic hash that uses a key to sign a message. The receiver verifies the hash by recomputing it using the same key. So in this code the same key is hard-coded on the variable “accesskey” and used for both signing and authenticating.

[1] https://gist.github.com/binaryatrocity/7079332cab038da1394d
