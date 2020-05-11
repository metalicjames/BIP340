from schnorr_utils import *
from time import time

def schnorr_sign(msg: bytes, seckey: bytes, aux_rand: bytes) -> bytes:
    d0 = int_from_bytes(seckey)
    if not (0 < d0 < n):
        raise ValueError("Secret key must be an integer in range (0, n)")
    P = d0*G
    d = d0 if has_even_y(P) else n-d0
    t = xor_bytes(bytes_from_int(d), tagged_hash("BIP340/aux", aux_rand))
    rand = tagged_hash("BIP340/nonce", t + bytes_from_point(P) + msg)
    k0 = int_from_bytes(rand) % n
    if k0 == 0:
        raise RuntimeError('Failure. This happens only with negligible probability.')
    R = k0*G
    k = k0 if has_square_y(R) else n-k0
    e = int_from_bytes(tagged_hash("BIP340/challenge", \
                       bytes_from_point(R) + bytes_from_point(P) + msg)) % n
    sig = bytes_from_point(R) + bytes_from_int((k+e*d) % n)
    if not schnorr_verify(msg, bytes_from_point(P), sig):
        raise RuntimeError('The created signature does not pass verification.')
    return sig

def schnorr_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    P = lift_x_even_y(pubkey)
    r = int_from_bytes(sig[0:32])
    s = int_from_bytes(sig[32:64])
    if P is None or r >= p or s >= n:
        return False
    e = int_from_bytes(tagged_hash("BIP340/challenge", sig[0:32] + pubkey + msg)) % n
    R = s*G-e*P
    try:
        if not has_square_y(R) or R.x != r:
            return False
        return True
    except:
        return False

def batch_verify(pubkeys: List[bytes], msgs: List[bytes], sigs: List[bytes]):
    u = len(pubkeys)
    seed = hashlib.sha256(b''.join(pubkeys)+b''.join(msgs)+b''.join(sigs)).digest()
    random.seed(int_from_bytes(seed))
    a = [random.randint(1, n-1) for i in range(u-1)]
    P = [lift_x_even_y(pubkeys[i]) for i in range(u)]
    r = [int_from_bytes(sigs[i][0:32]) for i in range(u)]
    s = [int_from_bytes(sigs[i][32:64]) for i in range(u)]
    if any(x is None for x in P) or any(x>=p for x in r) or any(x>=n for x in s):
        return False
    e = [int_from_bytes(tagged_hash("BIP340/challenge", bytes_from_int(r[i]) \
                    + bytes_from_point(P[i]) + msgs[i])) % n for i in range(u)]
    R = [lift_x_square_y(bytes_from_int(r[i])) for i in range(u)]
    if any(x is None for x in R):
        return False
    ver_sum = s[0]
    for a_i, s_i in zip(a, s[1:]):
        ver_sum += a_i*s_i

    test_sum = R[0]
    for a_i, R_i in zip(a, R[1:]):
        test_sum += a_i*R_i
    test_sum += e[0]*P[0]
    for a_i, e_i, P_i in zip(a, e[1:], P[1:]):
        test_sum += (a_i*e_i)*P_i
    return ver_sum*G == test_sum
