from ecpy.curves import Curve, Point
from typing import List, Optional, Any
import hashlib
import binascii
import random

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

curve   = Curve.get_curve('secp256k1')
G = Point(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, \
          0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8, \
          curve)

def is_infinity(P: Optional[Point]) -> bool:
    return P.is_infinity

def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")

def bytes_from_int(x: int) -> bytes:
    return x.to_bytes(32, byteorder="big")

def bytes_from_point(P: Point) -> bytes:
    return bytes_from_int(P.x)

def has_even_y(P: Point) -> bool:
    return not is_infinity(P) and P.y % 2 == 0

def xor_bytes(b0: bytes, b1: bytes) -> bytes:
    return bytes(x ^ y for (x, y) in zip(b0, b1))

def is_square(x: int) -> bool:
    return int(pow(x, (p - 1) // 2, p)) == 1

def has_square_y(P: Point) -> bool:
    assert P is not None
    return not is_infinity(P) and is_square(P.y)

def lift_x_square_y(b: bytes) -> Optional[Point]:
    x = int_from_bytes(b)
    if x >= p:
        return None
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if pow(y, 2, p) != y_sq:
        return None
    return Point(x, y, curve)

def lift_x_even_y(b: bytes) -> Optional[Point]:
    P = lift_x_square_y(b)
    if P is None:# or is_infinity(P):
        return None
    else:
        return Point(P.x, P.y if P.y % 2 == 0 else p - P.y, curve)

tagged_hashes = {}

def tagged_hash(tag: str, msg: bytes) -> bytes:
    if tag in tagged_hashes:
        tag_hash = tagged_hashes[tag]
    else:
        tag_hash = hashlib.sha256(tag.encode()).digest()
        tagged_hashes[tag] = tag_hash
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()

def pubkey_gen(seckey):
    d0 = int_from_bytes(seckey)
    #print(d0)
    if not (0 < d0 < n):
        raise ValueError("Secret key must be an integer in range (0, n)")
    #assert P is not None
    return bytes_from_point(d0*G)
