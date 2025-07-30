import os
import base64
import hashlib
import json
import time
import rsa

# You'll need to create/import the AES implementation
# Either create the aes.py file or import from an external library if allowed
from aes import AES, encrypt as aes_encrypt, decrypt as aes_decrypt

class MessageManager:
    def __init__(self, user_manager):
        self.user_manager = user_manager
        os.makedirs("messages", exist_ok=True)
        
    def encrypt_message(self, sender, recipient, message):
        """Encrypt a message from sender to recipient"""
        if isinstance(message, str):
            message = message.encode('utf-8')
            
        # Get recipient's public key
        recipient_pub_key = self.user_manager.get_public_key(recipient)
        if recipient_pub_key is None:
            return False, "Recipient not found"
            
        # 1. Generate a random symmetric key
        sym_key = os.urandom(16)  # 128-bit key for AES
        
        # 2. Encrypt the message with the symmetric key using AES
        encrypted_message = aes_encrypt(sym_key, message)
        
        # 3. Sign the encrypted message with sender's private key
        # Get sender's private key (assuming the sender is authenticated)
        user_file = os.path.join(self.user_manager.users_dir, f"{sender}.json")
        with open(user_file, 'r') as f:
            user_data = json.load(f)
            
        sender_priv_key = rsa.PrivateKey.load_pkcs1(
            base64.b64decode(user_data["private_key"])
        )
        
        # Create message hash and sign it
        message_hash = hashlib.sha256(encrypted_message).digest()
        signature = rsa.sign(message_hash, sender_priv_key, 'SHA-256')
        
        # 4. Encrypt the symmetric key with recipient's public key
        encrypted_sym_key = rsa.encrypt(sym_key, recipient_pub_key)
        
        # Package everything together
        message_package = {
            "sender": sender,
            "recipient": recipient,
            "encrypted_message": base64.b64encode(encrypted_message).decode(),
            "encrypted_key": base64.b64encode(encrypted_sym_key).decode(),
            "signature": base64.b64encode(signature).decode(),
            "timestamp": int(time.time())
        }
        
        # Save the message to recipient's inbox
        message_id = hashlib.md5(f"{sender}{recipient}{time.time()}".encode()).hexdigest()
        message_file = os.path.join("messages", f"{message_id}.json")
        with open(message_file, 'w') as f:
            json.dump(message_package, f)
            
        return True, message_id
        
    def decrypt_message(self, recipient, message_id, private_key):
        """Decrypt a message for the recipient"""
        message_file = os.path.join("messages", f"{message_id}.json")
        if not os.path.exists(message_file):
            return False, "Message not found"
            
        with open(message_file, 'r') as f:
            message_package = json.load(f)
            
        # Verify the recipient
        if message_package["recipient"] != recipient:
            return False, "This message is not for you"
            
        # Get sender's public key for signature verification
        sender_pub_key = self.user_manager.get_public_key(message_package["sender"])
        if sender_pub_key is None:
            return False, "Sender not found or invalid"
            
        # Decrypt the symmetric key with recipient's private key
        encrypted_key = base64.b64decode(message_package["encrypted_key"])
        try:
            sym_key = rsa.decrypt(encrypted_key, private_key)
        except:
            return False, "Failed to decrypt the symmetric key"
            
        # Get the encrypted message and signature
        encrypted_message = base64.b64decode(message_package["encrypted_message"])
        signature = base64.b64decode(message_package["signature"])
        
        # Verify the signature
        message_hash = hashlib.sha256(encrypted_message).digest()
        try:
            rsa.verify(message_hash, signature, sender_pub_key)
        except:
            return False, "Message signature verification failed"
            
        # Decrypt the message using AES
        try:
            decrypted_message = aes_decrypt(sym_key, encrypted_message)
            return True, decrypted_message.decode('utf-8')
        except:
            return False, "Failed to decrypt the message"
