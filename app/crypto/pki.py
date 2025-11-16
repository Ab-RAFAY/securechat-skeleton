from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
import datetime




def load_cert(path: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(open(path, 'rb').read())




def load_private_key(path: str):
    return serialization.load_pem_private_key(open(path, 'rb').read(), password=None)




def cert_is_valid(cert_pem: bytes, ca_cert_pem: bytes, expected_cn: str = None) -> (bool, str):
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)


        # Check validity period
        now = datetime.datetime.utcnow()
        if cert.not_valid_before > now or cert.not_valid_after < now:
            return False, 'EXPIRED'


        # Verify issuer matches CA subject
        if cert.issuer != ca_cert.subject:
            return False, 'UNTRUSTED_ISSUER'


        # Verify signature by CA
        ca_pub = ca_cert.public_key()
        ca_pub.verify(cert.signature, cert.tbs_certificate_bytes, padding=cert.signature_hash_algorithm.padding if hasattr(cert.signature_hash_algorithm, 'padding') else serialization.NoEncryption())
        # Above generic verify may not work for all algs; simpler approach is to let cryptography raise if invalid in normal flows
    except Exception as e:
        return False, f'BAD_CERT: {e}'


    if expected_cn:
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            if cn != expected_cn:
                return False, 'CN_MISMATCH'
        except Exception:
            return False, 'CN_NOT_FOUND'


    return True, 'OK'