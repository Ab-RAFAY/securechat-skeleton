import base64
import time
from hashlib import sha256




def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()




def b64d(s: str) -> bytes:
    return base64.b64decode(s)




def now_ms() -> int:
    return int(time.time() * 1000)




def sha256_hex(b: bytes) -> str:
    return sha256(b).hexdigest()