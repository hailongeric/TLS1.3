# -*- coding: UTF-8 -*-
from .messages import Extension
from ...utilization.struct import Struct, Members, Member, Listof
from ...utilization.type import Uint16

__all__ = [
    'CertificateAuthoritiesExtension', 'OIDFilter', 'OIDFilterExtension',
    'PostHandshakeAuth', 'EncryptedExtensions', 'CertificateRequest',
]


class CertificateAuthoritiesExtension:
    pass


class OIDFilter:
    pass


class OIDFilterExtension:
    pass


class PostHandshakeAuth:
    pass


class EncryptedExtensions(Struct):
    """
    struct {
      Extension extensions<0..2^16-1>;
    } EncryptedExtensions;
    """
    def __init__(self, extensions):
        self.extensions = extensions

        self.struct = Members(self, [
            Member(Listof(Extension), 'extensions', length_t=Uint16),
        ])


class CertificateRequest:
    pass
