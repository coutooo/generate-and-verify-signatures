import sys
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
import binascii

# pip install pycrypto
# if u get time.clock error change time.clock() to time.perf_counter()

def usage():
    print("Usage: \n"
            "signatures.py -generate  <priv-key> <data> <signature-file> \n"
            "signatures.py -verify  <PUB-key> <data> <signature-file> \n")

if (len(sys.argv) < 5):
    usage()
    quit()

op = sys.argv[1]
key_f = sys.argv[2]
data_f = sys.argv[3]
sig_f = sys.argv[4]

def generate_signature(key, data, sig_f):
    print("Generating Signature")
    h = SHA256.new(data)
    signer = PKCS1_v1_5.new(key)
    signature = signer.sign(h)
    with open(sig_f, 'wb') as f:
        f.write(binascii.b2a_base64(signature))

def verify_signature(key, data, sig_f):
    print("Verifying Signature")
    h = SHA256.new(data)
    signer = PKCS1_v1_5.new(key)
    rsp = "Verification Failure"

    with open(sig_f, 'rb') as f: 
        signature = f.read()
        signature = binascii.a2b_base64(signature)
        if (signer.verify(h, signature)):
            rsp = "Success"

    print(rsp)

# Read all file contents
with open(key_f, 'rb') as f: keydata = f.read()
with open(data_f, 'rb') as f: data = f.read()

key = RSA.importKey(keydata)

if (op == "-generate"):
    # Generate Signature
    generate_signature(key, data, sig_f)
elif (op == "-verify"):
    # Verify Signature
    verify_signature(key, data, sig_f)
else:
    #Error
    usage()