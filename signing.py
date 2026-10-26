#!/usr/bin/env python3
# Eclipse Strata MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Pure-stdlib Ed25519 sign/verify for the PinSigner local fallback (Strata §7.1).

"""Ed25519 (RFC 8032) pure-Python. Local signer fallback; Herald port swaps in remotely."""
import hashlib

_b = 256
_q = 2**255 - 19
_l = 2**252 + 27742317777372353535851937790883648493
def _H(m): return hashlib.sha512(m).digest()
def _inv(x): return pow(x, _q-2, _q)
_d = -121665 * _inv(121666) % _q
_I = pow(2, (_q-1)//4, _q)
def _xrecover(y):
    xx = (y*y-1) * _inv(_d*y*y+1) % _q
    x = pow(xx, (_q+3)//8, _q)
    if (x*x - xx) % _q != 0: x = x*_I % _q
    if x % 2 != 0: x = _q-x
    return x
_By = 4 * _inv(5) % _q
_B = (_xrecover(_By), _By)
def _edwards(P, Q):
    x1,y1 = P; x2,y2 = Q
    den = _inv(1 + _d*x1*x2*y1*y2 % _q)
    x3 = (x1*y2 + x2*y1) * den % _q
    den2 = _inv(1 - _d*x1*x2*y1*y2 % _q)
    y3 = (y1*y2 + x1*x2) * den2 % _q
    return x3, y3
def _scalarmult(P, e):
    Q = (0,1)
    while e:
        if e & 1: Q = _edwards(Q, P)
        P = _edwards(P, P); e >>= 1
    return Q
def _encodeint(y):
    bits = [(y >> i) & 1 for i in range(_b)]
    return bytes(sum(bits[i*8+j] << j for j in range(8)) for i in range(_b//8))
def _encodepoint(P):
    x,y = P
    bits = [(y >> i) & 1 for i in range(_b-1)] + [x & 1]
    return bytes(sum(bits[i*8+j] << j for j in range(8)) for i in range(_b//8))
def _bit(h,i): return (h[i//8] >> (i%8)) & 1
def _decodeint(s): return sum(2**i * _bit(s,i) for i in range(0,_b))
def _decodepoint(s):
    y = sum(2**i * _bit(s,i) for i in range(0,_b-1))
    x = _xrecover(y)
    if x & 1 != _bit(s,_b-1): x = _q-x
    return x,y
def _Hint(m):
    h = _H(m); return sum(2**i * _bit(h,i) for i in range(2*_b))
def generate_keypair(seed=None):
    import secrets
    h = _H(seed or secrets.token_bytes(32))
    a = 2**(_b-2) + sum(2**i * _bit(h,i) for i in range(3,_b-2))
    return h, a, _encodepoint(_scalarmult(_B, a))
def sign(seed_material, msg: bytes):
    h, a, pk = seed_material
    r = _Hint(h[_b//8:_b//4] + msg)
    R = _scalarmult(_B, r)
    S = (r + _Hint(_encodepoint(R) + pk + msg) * a) % _l
    return _encodepoint(R) + _encodeint(S), pk
def verify(pk_bytes, msg: bytes, sig: bytes) -> bool:
    if len(sig) != 64: return False
    try:
        R = _decodepoint(sig[:32]); A = _decodepoint(pk_bytes)
        S = _decodeint(sig[32:])
        if S >= _l: return False
        h = _Hint(sig[:32] + pk_bytes + msg)
        return _scalarmult(_B, S) == _edwards(R, _scalarmult(A, h))
    except Exception:
        return False
def fingerprint(pk_bytes) -> str:
    return hashlib.sha256(pk_bytes).hexdigest()
# Eclipse Strata MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
