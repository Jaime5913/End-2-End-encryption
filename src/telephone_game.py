import sys
import os
# Key serialization
import cryptography.hazmat.primitives.serialization as serialization

# Deserialize a public key from PEM encoded data to one of the supported asymmetric public key types.
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# ECDH with Curve25519
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

# Edwards-curve Digital Signature Algorithm (EdDSA)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

# HMAC-based Extract-and-Expand Key Derivation Function
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Hashing algorithms, like SHA-256
from cryptography.hazmat.primitives import hashes

# AES block cipher utilizing Galois Counter Mode (GCM)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Read keys from file 
with open('RootPublicKey.p8', 'rb') as f:
    Pkeys_pem = f.read()

firstMessage = b"Bob -> Charlie: What is your favorite sport?\n"


# 1st we need to generates key pairs using X25519 (for key exchange) 
# and Ed25519 (for signing) and share your public keys

myX25519PrivateKey = X25519PrivateKey.generate()
myX25519PublicKey = myX25519PrivateKey.public_key()

myEd25519PrivateKey = Ed25519PrivateKey.generate()
myEd25519PublicKey = myEd25519PrivateKey.public_key()

# Create  PK PEM Certificates and save them to a file  to share with the group
# code is given

myX25519PublicKeyPEM = myX25519PublicKey.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

myEd25519PublicKeyPEM = myEd25519PublicKey.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Save PK Certs in a file named myName-PubKeys.p8                    #Commented out so that the public keys wont be updated in file
# with open(charlie-PubKeys.p8", "wb") as file:
#     file.write(myX25519PublicKeyPEM)
#     file.write(myEd25519PublicKeyPEM)


# print the PEMs    
print("My X25519 Public Key (PEM):\n", myX25519PublicKeyPEM, "\n")
print("My Ed25519 Public Key (PEM):\n", myEd25519PublicKeyPEM, "\n")



#These are the keys I generated when creating my own sender(in file senders.p8)

senderX25519PublicKeyPEM = """
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VuAyEA5K3b8u5V33uxjic8LQxFDsnXmTiSUwK8hLfPIFfllRk=
-----END PUBLIC KEY-----
"""
senderEd25519PublicKeyPEM = """
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAsG/48ie21Too4corUZm0C9TDIg+JNPOyY03/ZG2vwWM=
-----END PUBLIC KEY-----
"""

senderX25519PublicKeyPEM = senderX25519PublicKeyPEM.encode() 
senderEd25519PublicKeyPEM = senderEd25519PublicKeyPEM.encode()
# Import Sender's  X25519 Public Key (for key exchange)

SenderX25519PublicKey = load_pem_public_key(senderX25519PublicKeyPEM)


# Import Sender's Ed25519 Public Key (For signing)
SenderEd25519PublicKey = load_pem_public_key(senderEd25519PublicKeyPEM)


print("Sender's X25519 Public Key (PEM):\n", senderX25519PublicKeyPEM, "\n")
print("Sender's Ed25519 Public Key (PEM):\n",senderEd25519PublicKeyPEM, "\n")


# NOTE: here we are signing before encrypting, so we need to decrypt then verify.

# First, get sender's encrypted message and signature 

# if the message was saved in a file
with open("message_for_jaime.msg", 'rb') as secmsg_in:
    recieved_cyphertext=secmsg_in.read()


# Key exchange with sender's pub key using ECDH
shared_key = myX25519PrivateKey.exchange(SenderX25519PublicKey)

print("Secret shared key (hex):", shared_key.hex())

hkdf_salt = b'\xbb%\x86\t>\xaf\xe9zB\xba\x12\n'
hkdf_info = b'AES key'
# AES session key derivation with HKDF
derived_key = HKDF(
    algorithm = hashes.SHA256(),
    salt = hkdf_salt,
    length = 32,
    info = hkdf_info,
).derive(shared_key)


print("Secret derived key - AES key (hex):", derived_key.hex(), "\n")

# Decrypt the message using AES GCM
aesgcm = AESGCM(derived_key)
nonce = b'\x81t4\xe9\xb4n\xfe\xf0\xa4\x88\x0e\x14'
data = recieved_cyphertext
aad = b'To Jaime'
signedMessage = aesgcm.decrypt(nonce, data, aad)
 

print("Decrypted Sender's (message|signature) (bytes):\n", signedMessage, "\n")

message, signature = signedMessage.split(b'|', 1)

print("Sender's message (bytes):\n", message, "\n")
print("Sender's message (string):\n", message.decode(), "\n")
print("Sender's signature (bytes):\n", signature, "\n")

# Signature verification
try:
   SenderEd25519PublicKey.verify(signature, message)

except:
    print("InvalidSignature ")
else: 
    print("The verification was successful. The message did come from the sender!")

updated_message = message + b"Whats your favorite food?\n" \
+ b"Charlie-> Alice: Whats your favorite movie?\n" 
print(updated_message.decode())

# Read the next Recipient's PK
with open('senders.p8', 'rb') as f:
    nextRecipPkeys_pem = f.read()

key_separation = nextRecipPkeys_pem.split(b'\nSIGKEY\n')

nextRecipX25519PublicKeyPEM = key_separation[0]
nextRecipEd25519PublicKeyPEM = key_separation[1]

nextRecipX25519PK = load_pem_public_key(nextRecipX25519PublicKeyPEM)
nextRecipEd25519PK = load_pem_public_key(nextRecipEd25519PublicKeyPEM)



nxtRecipX25519PublicKey= nextRecipX25519PublicKeyPEM.decode() 
nxtRecipEd25519PublicKey= nextRecipEd25519PublicKeyPEM.decode()

print("Next Recipient's X25519 Public Key (PEM):\n", nxtRecipX25519PublicKey, "\n")
print("Next Recipient's Ed25519 Public Key (PEM):\n", nxtRecipEd25519PublicKey, "\n")



# Signing (Note: here we are signing before encrypting, you may do the opposite i.e. encrypt then sign)
# You need to use your Ed25519 signing key (private key)
my_signature = myEd25519PrivateKey.sign(updated_message)  #......COMPLETE.....

print("my signature (bytes):\n", my_signature, "\n")

updatedSigned_message = updated_message + b'|' + my_signature
print("Data to be encrypted (message|signature) (bytes):\n", updatedSigned_message, "\n")

# Key exchange with next recipient using ECDH
shared_key = myX25519PrivateKey.exchange(nextRecipX25519PK)    #......COMPLETE.....

print("Secret shared key (hex):", shared_key.hex())
salt = os.urandom(12)
info = b'AES key'
# AES session key derivation with HKDF
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    info= info,
).derive(shared_key)

print("Secret derived key - AES key (hex):", derived_key.hex(), "\n")

# now let's encrypt the signed message to be sent to next recipient using the shared key and AES GCM
aesgcm = AESGCM(derived_key)
nonce = os.urandom(12)
data = updatedSigned_message
aad = b'To Bob'
nxtRecip_cyphertext = aesgcm.encrypt(nonce, data, aad ) #......COMPLETE.....

print("my encrypted message to next recipient (myself) (bytes):\n", nxtRecip_cyphertext, "\n")
print("HKDF salt:", salt)
print("HKDF info (bytes):",info)
print("AES GCM nonce (bytes):", nonce)
print("AES GCM associated data (bytes):", aad)
with open("Encrypted-Message-jaime-sender.msg", 'wb') as secmsg_out:
    secmsg_out.write(nxtRecip_cyphertext)