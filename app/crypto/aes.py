from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding




def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    padder = padding.PKCS7(block_size * 8).padder()
    return padder.update(data) + padder.finalize()




def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    unpadder = padding.PKCS7(block_size * 8).unpadder()
    return unpadder.update(data) + unpadder.finalize()




def encrypt_ecb(key: bytes, plaintext: bytes) -> bytes:
    assert len(key) == 16
    pt = pkcs7_pad(plaintext)
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(pt) + encryptor.finalize()




def decrypt_ecb(key: bytes, ciphertext: bytes) -> bytes:
    assert len(key) == 16
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    pt = decryptor.update(ciphertext) + decryptor.finalize()
    return pkcs7_unpad(pt)