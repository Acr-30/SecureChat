import os
import base64
import hashlib
import hmac
import json
import rsa
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa, padding
from cryptography.x509.oid import NameOID
import datetime

class UserManager:
    def __init__(self, users_dir="users", keys_dir="public_keys", certs_dir="certificates"):
        os.makedirs(users_dir, exist_ok=True)
        os.makedirs(keys_dir, exist_ok=True)
        os.makedirs(certs_dir, exist_ok=True)
        self.users_dir = users_dir
        self.keys_dir = keys_dir
        self.certs_dir = certs_dir
        self.ca_key, self.ca_cert = self._create_ca()

    def _create_ca(self):
        ca_key = crypto_rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat CA")
        ])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            ca_key.public_key()
        ).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).sign(ca_key, hashes.SHA256())
        with open(os.path.join(self.certs_dir, "ca.crt"), 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        return ca_key, cert

    def hash_password(self, password, salt=None):
        if salt is None:
            salt = os.urandom(16)
        pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return salt, pw_hash

    def register_user(self, username, password):
        user_file = os.path.join(self.users_dir, f"{username}.json")
        if os.path.exists(user_file):
            return False, "Username already exists"

        (pubkey, privkey) = rsa.newkeys(2048)
        salt, pw_hash = self.hash_password(password)

        pubkey_bytes = pubkey.save_pkcs1()
        crypto_pubkey = serialization.load_pem_public_key(pubkey_bytes)

        cert = x509.CertificateBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, username)
        ])).issuer_name(self.ca_cert.subject).public_key(
            crypto_pubkey
        ).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).sign(self.ca_key, hashes.SHA256())

        user_data = {
            "salt": base64.b64encode(salt).decode(),
            "password_hash": base64.b64encode(pw_hash).decode(),
            "private_key": base64.b64encode(privkey.save_pkcs1()).decode()
        }

        with open(user_file, 'w') as f:
            json.dump(user_data, f)

        public_key_file = os.path.join(self.keys_dir, f"{username}.pub")
        with open(public_key_file, 'wb') as f:
            f.write(pubkey.save_pkcs1())

        cert_file = os.path.join(self.certs_dir, f"{username}.crt")
        with open(cert_file, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        return True, "User registered successfully"

    def authenticate_user(self, username, password):
        user_file = os.path.join(self.users_dir, f"{username}.json")
        if not os.path.exists(user_file):
            return False, "User does not exist"

        with open(user_file, 'r') as f:
            user_data = json.load(f)

        salt = base64.b64decode(user_data["salt"])
        stored_hash = base64.b64decode(user_data["password_hash"])

        _, new_hash = self.hash_password(password, salt)
        if hmac.compare_digest(new_hash, stored_hash):
            private_key = rsa.PrivateKey.load_pkcs1(
                base64.b64decode(user_data["private_key"])
            )
            return True, private_key
        else:
            return False, "Incorrect password"

    def get_public_key(self, username):
        cert_file = os.path.join(self.certs_dir, f"{username}.crt")
        revoked_file = os.path.join(self.certs_dir, "revoked.json")
        if os.path.exists(revoked_file):
            with open(revoked_file, 'r') as f:
                revoked = json.load(f)
            if username in revoked:
                return None
        if not os.path.exists(cert_file):
            return None
        with open(cert_file, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        try:
            self.ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
            pubkey_bytes = cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.PKCS1
            )
            return rsa.PublicKey.load_pkcs1(pubkey_bytes)
        except:
            return None

    def revoke_user(self, username):
        revoked_file = os.path.join(self.certs_dir, "revoked.json")
        revoked = []
        if os.path.exists(revoked_file):
            with open(revoked_file, 'r') as f:
                revoked = json.load(f)
        if username not in revoked:
            revoked.append(username)
            with open(revoked_file, 'w') as f:
                json.dump(revoked, f)
