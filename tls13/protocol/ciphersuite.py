# -*- coding: UTF-8 -*-
import hashlib
from ..utilization.type import Uint16, Type

__all__ = [
    'CipherSuite',
]


@Type.add_labels_and_values
class CipherSuite(Type):
    '''
              +------------------------------+-------------+
              | Description                  | Value       |
              +------------------------------+-------------+
              | TLS_AES_128_GCM_SHA256       | {0x13,0x01} |
              |                              |             |
              | TLS_AES_256_GCM_SHA384       | {0x13,0x02} |
              |                              |             |
              | TLS_CHACHA20_POLY1305_SHA256 | {0x13,0x03} |
              |                              |             |
              | TLS_AES_128_CCM_SHA256       | {0x13,0x04} |
              |                              |             |
              | TLS_AES_128_CCM_8_SHA256     | {0x13,0x05} |
              +------------------------------+-------------+
    '''

    TLS_AES_128_GCM_SHA256 = Uint16(0x1301)
    TLS_AES_256_GCM_SHA384 = Uint16(0x1302)
    TLS_CHACHA20_POLY1305_SHA256 = Uint16(0x1303)
    TLS_AES_128_CCM_SHA256 = Uint16(0x1304)
    TLS_AES_128_CCM_8_SHA256 = Uint16(0x1305)
    _size = 2

    @classmethod
    def get_hash_algorithm(cls, cipher_suite):
        if cipher_suite == cls.TLS_AES_256_GCM_SHA384:
            return hashlib.sha384
        return hashlib.sha256

    @classmethod
    def get_hash_name(cls, cipher_suite):
        if cipher_suite == cls.TLS_AES_256_GCM_SHA384:
            return 'sha384'
        return 'sha256'

    @classmethod
    def get_hash_algo_size(cls, cipher_suite):
        if cipher_suite == cls.TLS_AES_256_GCM_SHA384:
            return 48
        return 32
