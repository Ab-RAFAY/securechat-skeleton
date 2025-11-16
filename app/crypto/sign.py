from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
import base64




def rsa_sign(private_key_pem: bytes, message: bytes) -> bytes:
    priv = serialization.load_pem_private_key(private_key_pem, password=None)
    sig = priv.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return sig




def rsa_verify(public_cert_pem: bytes, message: bytes, signature: bytes) -> bool:
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(public_cert_pem)
    pub = cert.public_key()
    try:
        pub.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False