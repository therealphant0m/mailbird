from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

class Crypto:
    def generate_keys(passphrase: str) -> tuple:
        '''Generates RSA private and public keys with a passphrase'''
        key = RSA.generate(2048)
        encrypted_key = key.export_key(passphrase=passphrase, pkcs=8,
                                       protection="scryptAndAES128-CBC")
        return (encrypted_key, key.public_key().export_key())
    
    def generate_session_key() -> bytes:
        '''Generates session key'''
        return get_random_bytes(16)

    def encrypt(data: bytes, recipient_key: bytes, session_key: bytes) -> tuple:
        '''Encrypts data with the generated RSA public key
        Returns: (enc_session_key, nonce, tag, ciphertext)'''
        recipient_key = RSA.import_key(recipient_key)

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        return (enc_session_key, cipher_aes.nonce, tag, ciphertext)

    def decrypt(enc_session_key, nonce, tag, ciphertext, session_key: bytes, private_key: str) -> str:
        '''Decrypts encrypted data, returns string'''
        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return data.decode("utf-8")