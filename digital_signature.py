import hashlib
import rsa

def create_signature(message, private_key):
    """Create a digital signature for a message"""
    # Create a hash of the message
    message_hash = hashlib.sha256(message).digest()
    
    # Sign the hash with the private key
    signature = rsa.sign(message_hash, private_key, 'SHA-256')
    return signature

def verify_signature(message, signature, public_key):
    """Verify a digital signature"""
    # Create a hash of the message
    message_hash = hashlib.sha256(message).digest()
    
    # Verify the signature with the public key
    try:
        rsa.verify(message_hash, signature, public_key)
        return True
    except:
        return False
