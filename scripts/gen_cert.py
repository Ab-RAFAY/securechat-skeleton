from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
from pathlib import Path
import argparse


CERTS_DIR = Path(__file__).resolve().parents[1] / 'certs'
CERTS_DIR.mkdir(parents=True, exist_ok=True)




def gen_cert(cn: str, out_prefix: str, key_size: int = 2048, days: int = 365):
    # load CA
    ca_key = serialization.load_pem_private_key((CERTS_DIR / 'root_ca.key.pem').read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate((CERTS_DIR / 'root_ca.cert.pem').read_bytes())


    # generate key
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)


    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


    cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(ca_cert.subject)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days))
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .sign(ca_key, hashes.SHA256())
    )


    key_pem = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
    )


    cert_pem = cert.public_bytes(serialization.Encoding.PEM)


    out_key = Path(out_prefix + '.key.pem')
    out_cert = Path(out_prefix + '.cert.pem')
    out_key.write_bytes(key_pem)
    out_cert.write_bytes(cert_pem)


    print(f'Wrote key -> {out_key}\nWrote cert -> {out_cert}')




if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--cn', required=True)
    p.add_argument('--out', required=True, help='prefix for output files (e.g. certs/server)')
    p.add_argument('--days', type=int, default=365)
    args = p.parse_args()
    gen_cert(args.cn, args.out, days=args.days)