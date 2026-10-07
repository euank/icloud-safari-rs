"""Emit synthetic enrollment vectors using Python cryptography, independent of Rust.

Run manually with cryptography installed. ECDSA signatures are randomized, so
regeneration produces a different valid fixture. No account data is used.
Protocol sources are listed in docs/PROVENANCE.md.
Optional --verify-pysrp requires srp==1.0.22 and cross-checks six synthetic
exchanges against both its client and server with RFC5054 enabled. This is
the setting FindMy's account module enables before escrow recovery; only
no_username_in_x is disabled during recovery. Normal Rust CI uses the saved
vectors and has no Python/srp dependency.
"""
import base64
import hashlib
import json
import plistlib
import sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import padding


def varint(n):
    out = bytearray()
    while n > 127:
        out.append((n & 127) | 128)
        n >>= 7
    return bytes(out) + bytes([n])


def uint(field, value):
    return varint(field * 8) + varint(value)


def blob(field, value):
    if isinstance(value, str):
        value = value.encode()
    return varint(field * 8 + 2) + varint(len(value)) + value


def signed(domain, data, key):
    sig = key.sign(domain.encode() + data, ec.ECDSA(hashes.SHA384()))
    return blob(1, data) + blob(2, sig), sig


def spki(key):
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def export(key):
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint) + key.private_numbers().private_value.to_bytes(48, 'big')


entropy = bytes(range(72))
adsid = "synthetic-account"
signing = ec.derive_private_key(2, ec.SECP384R1())
encryption = ec.derive_private_key(3, ec.SECP384R1())
permanent = uint(1, 1) + blob(2, spki(signing)) + blob(3, spki(encryption)) + blob(4, "device") + blob(5, "MacBookPro18,3") + uint(6, 1)
signed_permanent, sig = signed("TPPB.PeerPermanentInfo", permanent, signing)
peer_id = "SHA256:" + base64.b64encode(hashlib.sha256(permanent + sig).digest()).decode()
stable = uint(1, 4) + uint(2, 5) + blob(3, "frozen-test-policy") + uint(10, 20) + blob(11, "flexible-test-policy")
dynamic = uint(1, 7) + blob(2, peer_id) + blob(3, "excluded-peer")
peer = blob(1, peer_id) + blob(2, signed_permanent) + blob(3, signed("TPPB.PeerStableInfo", stable, signing)[0]) + blob(4, signed("TPPB.PeerDynamicInfo", dynamic, signing)[0])
directory = blob(1, blob(1, "test-sync-token") + blob(2, blob(3, peer)))


def derive(info, length):
    return HKDF(hashes.SHA384(), length, adsid.encode(), info.encode()).derive(entropy)


order = int("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16)
escrow_signer = ec.derive_private_key(int.from_bytes(derive("Escrow Signing Private Key", 56), 'big') % (order-1) + 1, ec.SECP384R1())
escrow_encryption = ec.derive_private_key(int.from_bytes(derive("Escrow Encryption Private Key", 56), 'big') % (order-1) + 1, ec.SECP384R1())
internal = blob(3, uint(1, 1) + blob(2, export(signing))) + blob(4, uint(1, 1) + blob(2, export(encryption)))
iv = bytes(range(32))
encryptor = Cipher(algorithms.AES(derive("Escrow Symmetric Key", 32)), modes.GCM(iv)).encryptor()
ciphertext = encryptor.update(internal) + encryptor.finalize()
bottle_id = "00000000-0000-4000-8000-000000000001"
contents = blob(1, peer_id) + blob(2, bottle_id) + blob(8, spki(escrow_signer)) + blob(9, spki(escrow_encryption)) + blob(10, spki(signing)) + blob(11, spki(encryption)) + blob(12, blob(1, ciphertext) + blob(2, encryptor.tag) + blob(3, iv))
bottle = blob(2, contents) + blob(3, spki(escrow_signer)) + blob(4, escrow_signer.sign(contents, ec.ECDSA(hashes.SHA384()))) + blob(5, signing.sign(contents, ec.ECDSA(hashes.SHA384()))) + blob(6, peer_id) + blob(7, bottle_id)

# SRP server and client calculation, deliberately using A=2 to distinguish
# minimal encoding from 256-byte padding in the escrow scrambling parameter.
n = int(json.loads((Path(__file__).parent.parent / 'fixtures/public/protocol-vectors.json').read_text())["srp_2048_modulus"], 16)
H = lambda data: hashlib.sha256(data).digest()
minimal = lambda value: value.to_bytes((value.bit_length()+7)//8, 'big')
pad = lambda value: value.to_bytes(256, 'big')
username, password, salt = b'123', b'synthetic-passcode', bytes(range(16))
x = int.from_bytes(H(salt+H(username+b':'+password)), 'big')
k = int.from_bytes(H(pad(n)+pad(2)), 'big')
v = pow(2, x, n)
A = 2
B = (k*v+pow(2, 3, n)) % n
u = int.from_bytes(H(pad(A)+pad(B)), 'big')
S = pow((A * pow(v,u,n)) % n, 3, n)
K = H(minimal(S))
M1 = H(bytes(a^b for a,b in zip(H(pad(n)),H(pad(2)))) + H(username)+salt+minimal(A)+minimal(B)+K)
M2 = H(minimal(A)+M1+K)

# Independent server-side equations, with short and full-width public values.
# pysrp's RFC5054 mode pads u's inputs, but NOT A/B in M1 or S in K.
def srp_vector(a, b):
    public_a = pow(2, a, n)
    public_b = (k*v+pow(2, b, n)) % n
    scrambling = int.from_bytes(H(pad(public_a)+pad(public_b)), 'big')
    shared = pow((public_a*pow(v, scrambling, n)) % n, b, n)
    session = H(minimal(shared))
    proof = H(bytes(a^b for a,b in zip(H(pad(n)),H(pad(2))))
              + H(username)+salt+minimal(public_a)+minimal(public_b)+session)
    expected = H(minimal(public_a)+proof+session)
    if '--verify-pysrp' in sys.argv:
        import srp._pysrp as srp
        srp.rfc5054_enable(True)
        srp.no_username_in_x(False)
        client = srp.User(username, password, hash_alg=srp.SHA256,
                          ng_type=srp.NG_2048, bytes_a=pad(a))
        _, client_a = client.start_authentication()
        server = srp.Verifier(username, salt, minimal(v), bytes_A=client_a,
                              hash_alg=srp.SHA256, ng_type=srp.NG_2048, bytes_b=pad(b))
        challenge_salt, challenge_b = server.get_challenge()
        client_proof = client.process_challenge(challenge_salt, challenge_b)
        server_proof = server.verify_session(client_proof)
        assert client_proof == proof and server_proof == expected
        client.verify_session(server_proof)
        assert client.authenticated() and server.authenticated()
        assert client.get_session_key() == session == server.get_session_key()
    return {'private_a':minimal(a).hex(), 'server_b':minimal(public_b).hex(),
            'm1':proof.hex(), 'm2':expected.hex(), 'session':session.hex()}

differential = [srp_vector(a,b) for a in [1,2,int.from_bytes(bytes(range(32)),'big')]
                for b in [3,7]]

def frame(header, sections):
    payload, offsets = b'', []
    for section in sections:
        offsets.append(len(payload))
        payload += len(section).to_bytes(4, 'big') + section
    offsets.append(len(payload))
    body = header + b''.join(n.to_bytes(4, 'big') for n in offsets) + payload
    return (len(body)+4).to_bytes(4, 'big') + body

def cbc(key, iv, data):
    padder = padding.PKCS7(128).padder()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(padder.update(data)+padder.finalize()) + encryptor.finalize()

inner_key = hashlib.pbkdf2_hmac('sha256', password, salt, 1000, 16)
inner = frame(bytes(8)+(1000).to_bytes(4,'big')+bytes(4),
              [b'',salt,b'',cbc(inner_key,salt,plistlib.dumps({'BottledPeerEntropy':entropy})),b'',b''])
outer_iv = bytes(range(16,32))
cbc_body = cbc(K, outer_iv, inner)
gcm = Cipher(algorithms.AES(K), modes.GCM(outer_iv)).encryptor()
gcm_body = gcm.update(inner) + gcm.finalize() + gcm.tag
recovery = {
    'cbc': frame(bytes(24), [M2,outer_iv,cbc_body]).hex(),
    'cbc_legacy': frame(bytes(24), [M2,cbc_body,outer_iv]).hex(),
    'gcm': frame(bytes(4)+(2).to_bytes(4,'big')+bytes(32), [M2,outer_iv,gcm_body]).hex(),
}
print(json.dumps({"notes":"Synthetic data only; generated by tests/generate_enrollment_vectors.py", "adsid":adsid, "entropy":entropy.hex(), "bottle_id":bottle_id,"peer_id":peer_id,
    "bottle":bottle.hex(),"directory":directory.hex(),"recovery":recovery,"srp":{"server_b":minimal(B).hex(),"m1":M1.hex(),"m2":M2.hex(),"session":K.hex()},"srp_differential":differential}, indent=2))
