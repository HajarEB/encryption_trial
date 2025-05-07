
from cryptography.fernet import Fernet
from hashlib import sha256
import base64

# Get the JWT_SECRET_KEY from the environment
JWT_SECRET_KEY = "Thanhbjim@$@&^@&%^&RFghgjvHajar"

# Hash JWT_SECRET_KEY to make a 32-byte key for Fernet encryption
hashed_key = sha256(JWT_SECRET_KEY.encode()).digest()
cipher = Fernet(base64.urlsafe_b64encode(hashed_key))

def encrypt(text: str) -> str:
    return cipher.encrypt(text.encode()).decode()

def decrypt(token: str) -> str:
    
    return cipher.decrypt(token.encode()).decode()
def hash_lookup(text: str) -> str:      # to check for similar values
    return sha256(text.encode()).hexdigest()
