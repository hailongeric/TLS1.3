# -*- coding: UTF-8 -*-
from .rfc7919_ffdhe_modulus_ import *
from ...utilization.type import Uint16
from Crypto.Util.number import long_to_bytes, bytes_to_long
from ..cryptolib import get_random

# 用于FFDHE的Mudulus（素数）的函数的定义
'''
    enum {

          /* Elliptic Curve Groups (ECDHE) */
          secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),
          x25519(0x001D), x448(0x001E),

          /* Finite Field Groups (DHE) */
          ffdhe2048(0x0100), ffdhe3072(0x0101), ffdhe4096(0x0102),
          ffdhe6144(0x0103), ffdhe8192(0x0104),

          /* Reserved Code Points */
          ffdhe_private_use(0x01FC..0x01FF),
          ecdhe_private_use(0xFE00..0xFEFF),
          (0xFFFF)
      } NamedGroup;
'''

functions = {
        Uint16(0x0100): ffdhe2048,
        Uint16(0x0101): ffdhe3072,
        Uint16(0x0102): ffdhe4096,
        Uint16(0x0103): ffdhe6144,
        Uint16(0x0104): ffdhe8192,
    }


class FFDHE:
    def __init__(self, func_val=Uint16(0x0100)):
        # public key (g=2, modulus=p)
        self.p = functions[func_val]()
        self.g = 2

        # private key = [2, p-2]
        self.my_secret = get_random(2, self.p)

    def gen_public_key(self):
        public_key = pow(self.g, self.my_secret, self.p)
        return long_to_bytes(public_key)

    def gen_master_secret(self, **kwargs):
        self.gen_shared_secret(**kwargs)

    def gen_shared_key(self, peer_pub):
        """
            peer_pub  : g^PeerSecKey mod p
            self.my_secret : [2, ..., p-2]
        """
        # peer_pub, my_secret 使用Byte类型时的转换处理
        if isinstance(peer_pub, bytes):
            peer_pub = bytes_to_long(peer_pub)
        master_secret = pow(peer_pub, self.my_secret, self.p)
        return long_to_bytes(master_secret)
