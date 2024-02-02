from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

def generate_keys():
    private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        #backend=default_backend()
    )
def sign(message,private):
    message = bytes(str(message),'utf-8')#convert string to bytes
    signature = private.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def  verify(message,sig,public):
    message = bytes(str(message),'utf-8')#convert string to bytes
    try:
        public.verify(
            message,
            sig,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except:
        print("Error executing public key")
        return False

if __name__ == "__main__":
    private,public = generate_keys()
    private1,public1 = generate_keys()
    print(private)
    print(public)

    message = "Hello I am Govinda"
    signature = sign(message,private)
    print(signature)
    correct = verify(message,sig,public)
    if correct:
        print("Succeeded")
    else:
        print("Failed")
    