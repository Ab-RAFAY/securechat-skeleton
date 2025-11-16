import socket
import json
from pathlib import Path
from app.crypto.dh import derive_aes_key_from_shared
from app.crypto.aes import encrypt_ecb, decrypt_ecb
from app.crypto.sign import rsa_sign, rsa_verify
from app.common.utils import b64e, b64d, now_ms, sha256_hex
import random
import os
from cryptography import x509
from cryptography.hazmat.primitives import serialization

CERTS_DIR = Path('certs')
CA_CERT = CERTS_DIR / 'root_ca.cert.pem'
CLIENT_CERT = CERTS_DIR / 'client.cert.pem'
CLIENT_KEY = CERTS_DIR / 'client.key.pem'

HOST = '127.0.0.1'
PORT = 9009

class Client:
    def __init__(self):
        self.sock = socket.create_connection((HOST, PORT))
        self.server_cert = None
        self.client_cert = open(CLIENT_CERT,'rb').read()
        self.client_key = open(CLIENT_KEY,'rb').read()
        self.seqno = 0

    def send_json(self, obj):
        self.sock.sendall((json.dumps(obj)+ '\n').encode())

    def recv_json(self):
        buf = b''
        while b'\n' not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError('server disconnected')
            buf += chunk
        line, rest = buf.split(b'\n',1)
        return json.loads(line.decode())

    def connect_and_verify(self):
        # send hello
        self.send_json({'type':'hello','client cert': self.client_cert.decode()})
        obj = self.recv_json()
        if obj.get('type') == 'bad cert':
            raise Exception('Server rejected cert: ' + obj.get('msg',''))
        if obj.get('type') != 'server hello':
            raise Exception('expected server hello')
        self.server_cert = obj['server cert'].encode()
        # basic verify against CA
        ca = x509.load_pem_x509_certificate(open(CA_CERT,'rb').read())
        cert = x509.load_pem_x509_certificate(self.server_cert)
        now = __import__('datetime').datetime.utcnow()
        if cert.not_valid_before > now or cert.not_valid_after < now:
            raise Exception('server cert expired')
        if cert.issuer != ca.subject:
            raise Exception('server cert untrusted issuer')
        print('Server cert verified')

    def temp_dh_and_register(self, action='register', email='', username='', password=''):
        # choose p,g small demo (in real use choose safe primes)
        p = 162259276829213363391578010288127
        g = 5
        a = random.randint(2, p-2)
        A = pow(g, a, p)
        self.send_json({'type':'dh client','p': str(p),'g': str(g),'A': str(A)})
        resp = self.recv_json()
        if resp.get('type') != 'dh server':
            raise Exception('expected dh server')
        B = int(resp['B'])
        Ks = pow(B, a, p)
        K = derive_aes_key_from_shared(Ks)
        # prepare payload
        payload = json.dumps({'email': email, 'username': username, 'pwd': password}).encode()
        ct = encrypt_ecb(K, payload)
        self.send_json({'type': action, 'payload': b64e(ct)})
        resp = self.recv_json()
        print('Server response:', resp)

    def session_dh(self):
        p = 162259276829213363391578010288127
        g = 5
        a = random.randint(2, p-2)
        A = pow(g, a, p)
        self.send_json({'type':'dh client','p': str(p),'g': str(g),'A': str(A)})
        resp = self.recv_json()
        B = int(resp['B'])
        Ks = pow(B, a, p)
        self.K = derive_aes_key_from_shared(Ks)
        print('Session key derived')

    def send_message(self, text):
        self.seqno += 1
        ct = encrypt_ecb(self.K, text.encode())
        ts = now_ms()
        # sign digest: per-assignment sign SHA256(seqno||ts||ct)
        msg = (str(self.seqno)+str(ts)+b64e(ct)).encode()
        sig = rsa_sign(self.client_key, msg)
        # append to local transcript before sending
        self.transcript.append_line(self.seqno, ts, b64e(ct), b64e(sig), sha256_hex(self.server_cert))
        self.send_json({'type':'msg','seqno': self.seqno,'ts': ts,'ct': b64e(ct),'sig': b64e(sig)})
        # wait for reply
        resp = self.recv_json()
        print('Server reply:', resp)
        # if server replied with msg, append to transcript
        if resp.get('type') == 'msg':
            self.transcript.append_line(resp['seqno'], resp['ts'], resp['ct'], resp['sig'], sha256_hex(self.server_cert))

    def interactive(self):
        try:
            while True:
                text = input('> ')
                if not text:
                    continue
                if text == '/quit':
                    break
                self.send_message(text)
        except KeyboardInterrupt:
            pass
        # on exit, generate receipt and send to server
        try:
            transcript_hash = self.transcript.compute_transcript_hash()
            sig = rsa_sign(self.client_key, transcript_hash.encode())
            receipt = {
                'type': 'receipt',
                'peer': 'client',
                'first_seq': 0,
                'last_seq': self.seqno,
                'transcript_sha256': transcript_hash,
                'sig': b64e(sig)
            }
            # save locally
            with open('client_receipt.json','w') as f:
                json.dump(receipt, f)
            # send to server
            try:
                self.send_json(receipt)
            except Exception:
                pass
            # try to receive server receipt
            try:
                resp = self.recv_json()
                if resp.get('type') == 'receipt':
                    # verify server receipt signature
                    server_cert = x509.load_pem_x509_certificate(self.server_cert)
                    ok = rsa_verify(self.server_cert, resp['transcript_sha256'].encode(), b64d(resp['sig']))
                    if ok:
                        print('Server receipt verified OK')
                        with open('server_receipt.json','w') as f:
                            json.dump(resp, f)
                    else:
                        print('Server receipt signature INVALID')
            except Exception:
                pass
        except Exception as e:
            print('Failed to generate/send receipt', e)

if __name__ == '__main__':
    c = Client()
    c.connect_and_verify()
    # for first run, register
    print('Registering...')
    c.temp_dh_and_register('register', email='test@example.com', username='rafay', password='password123')
    # now login
    c.temp_dh_and_register('login', email='test@example.com', username='', password='password123')
    c.session_dh()
    c.interactive()