# -*- coding: UTF-8 -*-
import hmac
import hashlib
import os
from ..protocol.handshake import Handshake
from .bytestream import Writer
from .type import Uint8, Uint16
from Crypto.Util.number import bytes_to_long, long_to_bytes

__all__ = [
    'hash_value', 'hmac_value',
    'hkdf_extract', 'hkdf_expand', 'hkdf_expand_label', 'derive_secret',
    'transcript_hash', 'get_os_urandom', 'get_random',
]


def divceil(divident, divisor) -> int:
    """Integer division with rounding up"""
    quot, r = divmod(divident, divisor)
    return quot + int(bool(r))


def hash_value(data, hash_algorithm='sha256') -> bytearray:
    """Return a digest of `data` using `hash_algorithm`"""
    hashInstance = hashlib.new(hash_algorithm)
    hashInstance.update(data)
    return bytearray(hashInstance.digest())


def hmac_value(k, b, hash_algorithm='sha256') -> bytearray:
    """Return a HMAC using `b` and `k` using `hash_algorithm`"""
    return bytearray(hmac.new(k, b, getattr(hashlib, hash_algorithm)).digest())


def hmac_sha256(k, b) -> bytearray:
    return hmac_value(k, b, 'sha256')


def hmac_sha384(k, b) -> bytearray:
    return hmac_value(k, b, 'sha384')


def hkdf_extract(salt, IKM, hash_algorithm='sha256') -> bytearray:
    """
    HKDF-Extract(salt, IKM) -> PRK

    Options:
       Hash     a hash function; HashLen denotes the length of the
                hash function output in octets

    Inputs:
       salt     optional salt value (a non-secret random value);
                if not provided, it is set to a string of HashLen zeros.
       IKM      input keying material

    Output:
       PRK      a pseudorandom key (of HashLen octets)

    The output PRK is calculated as follows:

    PRK = HMAC-Hash(salt, IKM)
    """
    return hmac_value(salt, IKM, hash_algorithm)


def hkdf_expand(PRK, info, L, hash_algorithm='sha256') -> bytearray:
    """
    HKDF-Expand(PRK, info, L) -> OKM

    Options:
       Hash     a hash function; HashLen denotes the length of the
                hash function output in octets

    Inputs:
       PRK      a pseudorandom key of at least HashLen octets
                (usually, the output from the extract step)
       info     optional context and application specific information
                (can be a zero-length string)
       L        length of output keying material in octets
                (<= 255*HashLen)

    Output:
       OKM      output keying material (of L octets)

    The output OKM is calculated as follows:

    N = ceil(L/HashLen)
    T = T(1) | T(2) | T(3) | ... | T(N)
    OKM = first L octets of T

    where:
    T(0) = empty string (zero length)
    T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
    T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
    T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
    ...

    """
    N = divceil(L, getattr(hashlib, hash_algorithm)().digest_size)
    T = bytearray()
    T_prev = bytearray()
    for x in range(1, N+2):
        T += T_prev
        T_prev = hmac_value(PRK, T_prev + info + bytearray([x]), hash_algorithm)
    return T[:L]


def hkdf_expand_label(secret, label,
                      hashValue, length,
                      hash_algorithm='sha256') -> bytearray:
    """
    TLS1.3 key derivation function (HKDF-Expand-Label).
    :param bytearray secret: the key from which to derive the keying material
    :param bytearray label: label used to differentiate the keying materials
    :param bytearray hashValue: bytes used to "salt" the produced keying
        material
    :param int length: number of bytes to produce
    :param str hash_algorithm: name of the secure hash hash_algorithm used as the
        basis of the HKDF
    :rtype: bytearray

    HKDF-Expand-Label(Secret, Label, Context, Length) =
        HKDF-Expand(Secret, HkdfLabel, Length)

        Where HkdfLabel is specified as:

        struct {
            Uint16 length = Length;
            opaque label<7..255> = "tls13 " + Label;
            opaque context<0..255> = Context;
        } HkdfLabel;
    """

    hkdfLabel = Writer()
    hkdfLabel.add_bytes(Uint16(length))
    hkdfLabel.add_bytes(bytearray(b"tls13 ") + label, length_t=Uint8)
    hkdfLabel.add_bytes(hashValue, length_t=Uint8)
    '''
         HKDF-Expand-Label(Secret, Label, Context, Length) =
                HKDF-Expand(Secret, HkdfLabel, Length)
        '''
    return hkdf_expand(secret, hkdfLabel.bytes, length, hash_algorithm)


def derive_secret(secret, label, messages,hash_algorithm='sha256') -> bytearray:
    # https://tools.ietf.org/html/draft-ietf-tls-tls13-26#section-7.1
    """
    TLS1.3 key derivation function (Derive-Secret).
    :param bytearray secret: secret key used to derive the keying material
    :param bytearray label: label used to differentiate they keying materials
    :param List[Handshake] messages: hashes of the handshake messages
        or `None` if no handshake transcript is to be used for derivation of
        keying material
    :param str hash_algorithm: name of the secure hash hash_algorithm used as the
        basis of the HKDF hash_algorithm - governs how much keying material will
        be generated
    :rtype: bytearray

    Derive-Secret(Secret, Label, Messages) =
        HKDF-Expand-Label(Secret, Label,
                          Transcript-Hash(Messages), Hash.length)
    """
    if messages is None:
        hs_hash = hash_value(bytearray(b''), hash_algorithm)
    else:
        hs_hash = transcript_hash(messages, hash_algorithm)
    return hkdf_expand_label(secret, label, hs_hash,
                             getattr(hashlib, hash_algorithm)().digest_size,
                             hash_algorithm)


def transcript_hash(messages, hash_algorithm='sha256') -> bytearray:
    """
    Return value is computed by hashing the concatenation
    of each included handshake message, including the handshake message
    header carrying the handshake message type and length fields, but not
    including record layer headers. I.e.,

    Transcript-Hash(M1, M2, ... MN) = Hash(M1 || M2 ... MN)
    """
    # 不要包含Record层（TLSPlaintext），只加入Handshake部分来查找哈希值
    if isinstance(messages, (bytes, bytearray)):
        data = messages
    else:
        assert all(type(m) == Handshake for m in messages)
        data = b''.join(m.to_bytes() for m in messages)
    return hash_value(data, hash_algorithm)


def gen_key_and_iv(secret, key_size, nonce_size, hash_algo='sha256'):
    '''
        [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
        [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)
    '''
    write_key = hkdf_expand_label(secret, b'key', b'', key_size, hash_algo)
    write_iv  = hkdf_expand_label(secret, b'iv', b'', nonce_size, hash_algo)
    return write_key, write_iv


# 用于FFDHE中使用的SecretKey生成（随机数）的函数

def get_os_urandom(howMany):
    b = bytearray(os.urandom(howMany))
    assert len(b) == howMany
    return b


def get_random(low, high):
    assert low <= high
    random_bits_size = len(bin(high)[2:])
    random_size = len(long_to_bytes(high))
    lastBits = random_bits_size % 8
    while True:
        randomBytes = get_os_urandom(random_size)
        if lastBits != 0:
            randomBytes[0] = randomBytes[0] % (1 << lastBits)
        n = bytes_to_long(randomBytes)
        if n >= low and n <= high:
            return n
