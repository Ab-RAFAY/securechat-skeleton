"""
Simple classic DH helpers. Not secure parameter generation — use provided safe primes
or short demo primes for assignment. This module provides compute_shared and derive_key.
"""
from hashlib import sha256




def compute_shared(a_priv: int, b_pub: int, p: int) -> int:
    return pow(b_pub, a_priv, p)




def derive_aes_key_from_shared(shared_int: int) -> bytes:
    # big-endian representation
    bs = shared_int.to_bytes((shared_int.bit_length() + 7) // 8 or 1, 'big')
    digest = sha256(bs).digest()
    return digest[:16]