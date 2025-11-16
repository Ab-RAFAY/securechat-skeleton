import socket
import threading
import json
import os
from pathlib import Path
from app.crypto.aes import decrypt_ecb, encrypt_ecb
from app.crypto.dh import compute_shared, derive_aes_key_from_shared
from app.crypto.sign import rsa_verify, rsa_sign
from app.crypto.pki import load_cert, load_private_key
from app.storage.db import DB_CONFIG
from app.storage.transcript import Transcript
from app.common.utils import b64d, b64e, now_ms, sha256_hex
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import mysql.connector

CERTS_DIR = Path('certs')
CA_CERT = CERTS_DIR / 'root_ca.cert.pem'
SERVER_CERT = CERTS_DIR / 'server.cert.pem'
SERVER_KEY = CERTS_DIR / 'server.key.pem'

TRANSCRIPT_FILE = 'server_transcript.log'

HOST = '127.0.0.1'
PORT = 9009

class ClientHandler(threading.Thread):
    def __init__(self, conn, addr):
        super().__init__()
        self.conn = conn
        self.addr = addr
        self.client_cert = None
        self.server_cert = open(SERVER_CERT,'rb').read()
        self.server_key = open(SERVER_KEY,'rb').read()
        self.transcript = Transcript(TRANSCRIPT_FILE)
        self.seq_expect = 0

    def send_json(self, obj):
        data = (json.dumps(obj) + '\n').encode()
        self.conn.sendall(data)

    def recv_json(self):
        buf = b''
        while b'\n' not in buf:
            chunk = self.conn.recv(4096)
            if not chunk:
                raise ConnectionError('client disconnected')
            buf += chunk
            line, rest = buf.split(b'\n', 1)
        # Note: rest is discarded (simple single-line protocol)
        return json.loads(line.decode())

    def verify_cert(self, cert_pem):
        # basic validation using cryptography
        try:
            ca = x509.load_pem_x509_certificate(open(CA_CERT,'rb').read())
            cert = x509.load_pem_x509_certificate(cert_pem)
            # expiry
            now = __import__('datetime').datetime.utcnow()
            if cert.not_valid_before > now or cert.not_valid_after < now:
                return False, 'EXPIRED'
            # issuer
            if cert.issuer != ca.subject:
                return False, 'UNTRUSTED_ISSUER'
            # signature
            ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes, 
                                    serialization.padding.PKCS1v15(), cert.signature_hash_algorithm)
            return True, 'OK'
        except Exception as e:
            return False, f'BAD_CERT {e}'

    def handle_control_plane(self):
        # 1) receive hello with client cert
        obj = self.recv_json()
        if obj.get('type') != 'hello' or 'client cert' not in obj:
            self.send_json({'type':'error','msg':'expected hello'})
            return False
        client_cert_pem = obj['client cert'].encode()
        ok, msg = self.verify_cert(client_cert_pem)
        if not ok:
            self.send_json({'type':'bad cert','msg':msg})
            return False
        self.client_cert = client_cert_pem
        # send server hello
        server_hello = {'type':'server hello','server cert': self.server_cert.decode()}
        self.send_json(server_hello)
        return True

    def handle_temp_dh_and_auth(self):
        # receive dh client
        obj = self.recv_json()
        if obj.get('type') != 'dh client':
            self.send_json({'type':'error','msg':'expected dh client'})
            return False
        p = int(obj['p']); g = int(obj['g']); A = int(obj['A'])
        # generate b
        import random
        b = random.randint(2, p-2)
        B = pow(g, b, p)
        # send dh server
        self.send_json({'type':'dh server','B': str(B)})
        Ks = pow(A, b, p)
        K = derive_aes_key_from_shared(Ks)
        # now receive encrypted register/login
        obj = self.recv_json()
        if obj.get('type') not in ('register','login'):
            self.send_json({'type':'error','msg':'expected register/login'})
            return False
        payload_b64 = obj.get('payload')
        payload = decrypt_ecb(K, b64d(payload_b64))
        data = json.loads(payload.decode())
        # handle register
        if obj['type'] == 'register':
            return self.handle_register(data)
        else:
            return self.handle_login(data)

    def handle_register(self, data):
        email = data['email']; username = data['username']; password = data['pwd']
        # password is plaintext here (client hashed before? assignment says base64(sha256(salt||pwd)) for register but we will accept raw)
        # generate salt
        import os
        salt = os.urandom(16)
        import hashlib
        pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
        # store in DB
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s,%s,%s,%s)',
                           (email, username, salt, pwd_hash))
            conn.commit()
        except mysql.connector.errors.IntegrityError:
            self.send_json({'type':'register','status':'exists'})
            return False
        finally:
            conn.close()
        self.send_json({'type':'register','status':'ok'})
        return True

    def handle_login(self, data):
        email = data['email']; password = data['pwd']
        # fetch user
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute('SELECT salt,pwd_hash FROM users WHERE email=%s', (email,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            self.send_json({'type':'login','status':'no_user'})
            return False
        salt, stored_hash = row
        import hashlib
        pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
        if pwd_hash != stored_hash:
            self.send_json({'type':'login','status':'bad_creds'})
            return False
        self.send_json({'type':'login','status':'ok'})
        return True

    def handle_session(self):
        # full DH again to derive session key
        obj = self.recv_json()
        if obj.get('type') != 'dh client':
            self.send_json({'type':'error','msg':'expected dh client for session'})
            return False
        p = int(obj['p']); g = int(obj['g']); A = int(obj['A'])
        import random
        b = random.randint(2, p-2)
        B = pow(g, b, p)
        self.send_json({'type':'dh server','B': str(B)})
        Ks = pow(A, b, p)
        K = derive_aes_key_from_shared(Ks)
        # now message loop
        while True:
            try:
                obj = self.recv_json()
            except Exception:
                break
            if obj.get('type') == 'msg':
                seq = int(obj['seqno']); ts = int(obj['ts']); ct_b64 = obj['ct']; sig_b64 = obj['sig']
                # verify seq
                if seq <= self.seq_expect:
                    self.send_json({'type':'replay','msg':'seq too small'})
                    continue
                self.seq_expect = seq
                # verify signature
                h = sha256_hex((str(seq)+str(ts)).encode() + b64d(ct_b64)).encode()
                ok = rsa_verify(self.client_cert, (str(seq)+str(ts)+ct_b64).encode(), b64d(sig_b64))
                if not ok:
                    self.send_json({'type':'sigfail'})
                    continue
                # decrypt
                pt = decrypt_ecb(K, b64d(ct_b64))
                # append to transcript
                peer_fp = sha256_hex(self.client_cert)
                self.transcript.append_line(seq, ts, ct_b64, sig_b64, peer_fp)
                print(f'[Client {self.addr}] {pt.decode()}')
                # echo back an acknowledgement message signed by server
                reply = f'ACK {seq}'
                ct = encrypt_ecb(K, reply.encode())
                h2 = sha256_hex((str(seq)+str(now_ms())).encode() + ct).encode()
                sig = rsa_sign(self.server_key, (str(seq)+str(now_ms())+b64e(ct)).encode())
                self.send_json({'type':'msg','seqno':seq+1,'ts':now_ms(),'ct': b64e(ct),'sig': b64e(sig)})
            elif obj.get('type') == 'receipt':
                # client sending receipt; just save
                with open('client_receipt.json','w') as f:
                    json.dump(obj, f)
            else:
                self.send_json({'type':'unknown'})
        try:
            transcript_hash = self.transcript.compute_transcript_hash()
            sig = rsa_sign(self.server_key, transcript_hash.encode())
            receipt = {
                'type': 'receipt',
                'peer': 'server',
                'first_seq': 0,
                'last_seq': self.seq_expect,
                'transcript_sha256': transcript_hash,
                'sig': b64e(sig)
            }
            # save locally
            with open('server_receipt.json','w') as f:
                json.dump(receipt, f)
            # try to send to client (may fail if socket closed)
            try:
                self.send_json(receipt)
            except Exception:
                pass
        except Exception as e:
            print('Failed to create/send receipt', e)
        return True

    def run(self):
        try:
            ok = self.handle_control_plane()
            if not ok:
                self.conn.close(); return
            ok = self.handle_temp_dh_and_auth()
            if not ok:
                self.conn.close(); return
            ok = self.handle_session()
        except Exception as e:
            print('Connection error', e)
        finally:
            self.conn.close()


def start_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)
    print(f'Server listening on {HOST}:{PORT}')
    while True:
        conn, addr = s.accept()
        print('Accepted', addr)
        th = ClientHandler(conn, addr)
        th.start()

if __name__ == '__main__':
    start_server()
