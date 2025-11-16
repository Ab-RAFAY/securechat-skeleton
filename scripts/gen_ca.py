from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import Name, NameAttribute
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
from pathlib import Path
import argparse


CERTS_DIR = Path(__file__).resolve().parents[1] / 'certs'
CERTS_DIR.mkdir(parents=True, exist_ok=True)




def gen_ca(name: str, key_size: int = 2048, days: int = 3650):
    # generate private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)


    subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])


    cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(key, hashes.SHA256())
    )


    key_pem = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
    )


    cert_pem = cert.public_bytes(serialization.Encoding.PEM)


    key_path = CERTS_DIR / 'root_ca.key.pem'
    cert_path = CERTS_DIR / 'root_ca.cert.pem'


    key_path.write_bytes(key_pem)
    cert_path.write_bytes(cert_pem)


    print(f'Wrote CA key -> {key_path}\nWrote CA cert -> {cert_path}')




if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--name', required=True)
    p.add_argument('--days', type=int, default=3650)
    args = p.parse_args()
    gen_ca(args.name, days=args.days)