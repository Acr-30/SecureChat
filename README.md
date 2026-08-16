# 🔐 SecureChat

> A Python-based secure messaging and cryptographic communication prototype implementing authentication, hybrid encryption, digital signatures, X.509 certificates, and secure local message storage.

---

## 📌 Overview

**SecureChat** is a Python-based cybersecurity and applied cryptography project designed to demonstrate how multiple cryptographic mechanisms can be combined to protect user identity, message confidentiality, message integrity, and message authenticity.

The application provides a command-line messaging interface with user registration, authentication, encrypted messaging, digital signature verification, certificate generation, certificate revocation, and local message storage.

The project combines **RSA, AES, PBKDF2, HMAC, digital signatures, X.509 certificates, and a local Certificate Authority (CA)** into a single secure-messaging prototype.

SecureChat is intended for **cybersecurity education, cryptography learning, security laboratories, and practical experimentation with secure communication concepts**.

---

## ✨ Features

### 🔑 Secure Authentication

* User registration and login
* Password hashing using PBKDF2-HMAC-SHA256
* Random password salts
* 100,000 PBKDF2 iterations
* Constant-time password hash comparison
* User credential management using JSON storage

### 🔒 Hybrid Message Encryption

* AES-based message encryption
* Random AES session key generation
* RSA-based encryption of the AES session key
* Hybrid symmetric/asymmetric encryption architecture
* Separate protection of message content and encryption keys

### ✍️ Digital Signatures

* RSA-based digital signatures
* SHA-256 message hashing
* Message authenticity verification
* Integrity verification before message decryption
* Sender identity validation through cryptographic signatures

### 🏛️ Certificate & PKI Features

* RSA-2048 user key generation
* X.509 user certificates
* Local Certificate Authority implementation
* CA-signed user certificates
* Public key management
* Basic certificate revocation mechanism
* Revocation list storage

### 💾 Secure Message Storage

* Encrypted messages stored locally
* JSON-based message format
* Encrypted session keys stored with messages
* Digital signatures stored with messages
* Message timestamps
* Sender and recipient identification

### 🖥️ Command-Line Interface

* User registration
* Secure login
* Send messages
* View messages
* Logout
* User revocation
* Application exit

---

## 🛡️ Security Architecture

SecureChat uses a hybrid cryptographic design in which symmetric encryption protects the message while asymmetric cryptography protects the symmetric key.

```text
                    SENDER
                       │
                       ▼
              Generate AES Key
                       │
                       ▼
              Encrypt Message
                  with AES
                       │
                       ▼
             Hash Encrypted Data
                  using SHA-256
                       │
                       ▼
             Create RSA Signature
                       │
                       ▼
            Encrypt AES Key with
          Recipient RSA Public Key
                       │
                       ▼
             Encrypted Message
                       │
                       ▼
                Local Storage
                       │
                       ▼
                  RECIPIENT
                       │
          ┌────────────┴────────────┐
          ▼                         ▼
   Decrypt AES Key          Verify Signature
   using RSA Private Key    using Sender Key
          │                         │
          └────────────┬────────────┘
                       ▼
                Decrypt Message
                    using AES
```

---

## 🔐 Cryptographic Components

| Component                 | Purpose                                                       |
| ------------------------- | ------------------------------------------------------------- |
| **RSA-2048**              | Public-key encryption, key protection, and digital signatures |
| **AES**                   | Symmetric message encryption                                  |
| **PBKDF2-HMAC-SHA256**    | Password-based key derivation                                 |
| **HMAC-SHA256**           | Message authentication and integrity protection               |
| **SHA-256**               | Cryptographic hashing                                         |
| **X.509**                 | User certificate representation                               |
| **Certificate Authority** | Signs and validates user certificates                         |

---

## 🛠️ Technology Stack

| Technology       | Purpose                                        |
| ---------------- | ---------------------------------------------- |
| **Python 3**     | Core programming language                      |
| **RSA**          | Public-key cryptography and digital signatures |
| **Cryptography** | X.509 certificates and PKI functionality       |
| **AES**          | Symmetric encryption                           |
| **PBKDF2**       | Password-based key derivation                  |
| **HMAC**         | Integrity and authentication                   |
| **JSON**         | Local user and message storage                 |
| **CLI**          | Application interface                          |

---

## 📋 Requirements

Before running SecureChat, make sure you have:

* Python 3.x
* `rsa`
* `cryptography`

The project also contains a dedicated AES implementation in `aes.py`.

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/Acr-30/SecureChat.git
```

### 2. Enter the project directory

```bash
cd SecureChat
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

On Linux systems:

```bash
python3 -m pip install -r requirements.txt
```

---

## 🚀 Usage

Run the application with:

### Windows

```bash
python main.py
```

### Linux

```bash
python3 main.py
```

After launching the application, the terminal interface provides the available authentication and messaging operations.

### User Registration

Create a new account through the registration option.

A registered user is associated with cryptographic credentials including:

* Password-derived authentication data
* RSA public/private key pair
* User certificate
* Certificate information

### Login

Authenticate using the registered username and password.

Successful authentication provides access to the messaging functions.

### Send Message

Users can provide a recipient and message content.

The application:

1. Generates a random AES key.
2. Encrypts the message.
3. Creates a cryptographic signature.
4. Encrypts the AES key using the recipient's RSA public key.
5. Stores the protected message locally.

### View Messages

Stored messages can be retrieved through the messaging interface.

The application reconstructs the cryptographic message package, verifies the signature, decrypts the AES key, and decrypts the message.

### Revoke User

The application provides a user-revocation function that records revoked users through the project's certificate-revocation mechanism.

---

## 📁 Project Structure

```text
SecureChat/
│
├── main.py
├── authentication.py
├── encryption.py
├── digital_signature.py
├── aes.py
├── README.md
└── requirements.txt
```

---

## 🔬 Security Capabilities

| Capability                  | Description                                                        |
| --------------------------- | ------------------------------------------------------------------ |
| **Password Protection**     | Uses PBKDF2-HMAC-SHA256 with random salts                          |
| **Hybrid Encryption**       | Combines AES message encryption with RSA key protection            |
| **Digital Signatures**      | Provides RSA-based message authenticity and integrity verification |
| **Public-Key Cryptography** | Uses RSA key pairs for secure key operations                       |
| **Certificate Management**  | Generates and manages X.509 certificates                           |
| **Certificate Authority**   | Implements a local CA for certificate signing                      |
| **Certificate Revocation**  | Maintains a basic revoked-user list                                |
| **Encrypted Storage**       | Stores protected message content locally                           |
| **Cryptographic Hashing**   | Uses SHA-256 for cryptographic hashing                             |
| **Message Authentication**  | Uses HMAC-based integrity protection                               |

---

## 🎯 Learning Objectives

This project demonstrates practical application of:

* Applied cryptography
* Secure authentication
* Password hashing
* PBKDF2 key derivation
* AES symmetric encryption
* RSA asymmetric cryptography
* Hybrid encryption
* Digital signatures
* Cryptographic hashing
* HMAC
* Public Key Infrastructure (PKI)
* X.509 certificates
* Certificate Authorities
* Certificate revocation
* Secure message storage
* Python security programming

---

## ⚠️ Project Scope & Security Considerations

SecureChat is an **educational cryptography and secure-messaging prototype**, not a production-ready secure messaging platform.

The current implementation is intended to demonstrate cryptographic concepts and their practical integration.

Important implementation considerations include:

* User private keys are stored locally within the application's user data.
* The current project does not implement a network transport layer or real-time messaging server.
* There is no modern forward-secret messaging protocol or ratcheting mechanism.
* Certificate authority state is handled locally by the application.
* The project should not be considered a replacement for professionally audited secure-messaging software.

These limitations are useful considerations when studying how real-world secure communication systems evolve from cryptographic prototypes into production systems.

---

## 🔐 Ethical Use

> ⚠️ **Important:** SecureChat is intended for **educational purposes, cryptography research, cybersecurity laboratories, and authorized experimentation**.

The project should only be used in environments where you have permission to deploy, test, or modify the application and its data.

The author is not responsible for misuse of this software.

---

## 👨‍💻 Author

**Acr-30**

Cybersecurity & Ethical Hacking Student

Developed as part of practical learning and experimentation in:

**Applied Cryptography • Secure Authentication • Network Security • Cybersecurity • Python Security Development**

---

## ⭐ Support

If you find this project useful for cybersecurity learning, cryptography research, or experimentation, consider giving the repository a ⭐ on GitHub.
