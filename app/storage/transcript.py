from pathlib import Path
from hashlib import sha256
import json


TRANS_DIR = Path(__file__).resolve().parents[1] / '..' / 'transcripts'
TRANS_DIR = TRANS_DIR.resolve()
TRANS_DIR.mkdir(parents=True, exist_ok=True)




class Transcript:
    def __init__(self, filename: str):
        self.path = TRANS_DIR / filename
        # ensure file exists
        if not self.path.exists():
            self.path.write_text('')

    def append_line(self, seqno: int, ts: int, ct_b64: str, sig_b64: str, peer_fp: str):
        line = json.dumps({'seqno': seqno, 'ts': ts, 'ct': ct_b64, 'sig': sig_b64, 'peer': peer_fp})
        with open(self.path, 'a') as f:
            f.write(line + '\n')


    def compute_transcript_hash(self) -> str:
        with open(self.path, 'rb') as f:
            data = f.read()
        return sha256(data).hexdigest()


    def receipt(self, first_seq: int, last_seq: int, sig_b64: str):
        return {
        'type': 'receipt',
        'first_seq': first_seq,
        'last_seq': last_seq,
        'transcript_sha256': self.compute_transcript_hash(),
        'sig': sig_b64
        }