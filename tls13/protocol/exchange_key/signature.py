# -*- coding: UTF-8 -*-
from ...utilization.type import Uint16, Type
from ...utilization.bytestream import Reader
from ...utilization.struct import Struct, Members, Member, Listof

__all__ = ['SignatureScheme', 'SignatureSchemeList']


@Type.add_labels_and_values
class SignatureScheme(Type):
    # 签名算法
    """
     enum {
          /* RSASSA-PKCS1-v1_5 algorithms */
          rsa_pkcs1_sha256(0x0401),
          rsa_pkcs1_sha384(0x0501),
          rsa_pkcs1_sha512(0x0601),

          /* ECDSA algorithms */
          ecdsa_secp256r1_sha256(0x0403),
          ecdsa_secp384r1_sha384(0x0503),
          ecdsa_secp521r1_sha512(0x0603),

          /* RSASSA-PSS algorithms with public key OID rsaEncryption */
          rsa_pss_rsae_sha256(0x0804),
          rsa_pss_rsae_sha384(0x0805),
          rsa_pss_rsae_sha512(0x0806),

          /* EdDSA algorithms */
          ed25519(0x0807),
          ed448(0x0808),

          /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
          rsa_pss_pss_sha256(0x0809),
          rsa_pss_pss_sha384(0x080a),
          rsa_pss_pss_sha512(0x080b),

          /* Legacy algorithms */
          rsa_pkcs1_sha1(0x0201),
          ecdsa_sha1(0x0203),

          /* Reserved Code Points */
          private_use(0xFE00..0xFFFF),
          (0xFFFF)
      } SignatureScheme;
    """
    # RSASSA-PKCS1-v1_5 algorithms
    rsa_pkcs1_sha256 = Uint16(0x0401)
    rsa_pkcs1_sha384 = Uint16(0x0501)
    rsa_pkcs1_sha512 = Uint16(0x0601)

    # ECDSA algorithms
    ecdsa_secp256r1_sha256 = Uint16(0x0403)
    ecdsa_secp384r1_sha384 = Uint16(0x0503)
    ecdsa_secp512r1_sha512 = Uint16(0x0603)

    # RSASSA-PSS algorithms with public key OID rsaEncryption
    rsa_pss_rsae_sha256 = Uint16(0x0804)
    rsa_pss_rsae_sha384 = Uint16(0x0805)
    rsa_pss_rsae_sha512 = Uint16(0x0806)

    # EdDSA algorithms
    ed25519 = Uint16(0x0807)
    ed448 = Uint16(0x0808)

    # RSASSA-PSS algorithms with public key OID RSASSA-PSS
    rsa_pss_pss_sha256 = Uint16(0x0809)
    rsa_pss_pss_sha384 = Uint16(0x080a)
    rsa_pss_pss_sha512 = Uint16(0x080b)

    # Legacy algorithms
    rsa_pkcs1_sha1 = Uint16(0x0201)
    ecdsa_sha1 = Uint16(0x0203)

    # Reserved Code Points
    obsolete_RESERVED = (Uint16(0x0000), Uint16(0x0200))
    dsa_sha1_RESERVED = Uint16(0x0202)
    obsolete_RESERVED = (Uint16(0x0204), Uint16(0x0400))
    dsa_sha256_RESERVED = Uint16(0x0402)
    obsolete_RESERVED = (Uint16(0x0404), Uint16(0x0500))
    dsa_sha384_RESERVED = Uint16(0x0502)
    obsolete_RESERVED = (Uint16(0x0504), Uint16(0x0600))
    dsa_sha512_RESERVED = Uint16(0x0602)
    obsolete_RESERVED = (Uint16(0x0604), Uint16(0x06FF))
    private_use = (Uint16(0xFE00), Uint16(0xFFFF))
    _size = 2  # bytes


class SignatureSchemeList(Struct):
    # 用于指示支持的签名算法列表
    """
    struct {
      SignatureScheme supported_signature_algorithms<2..2^16-2>;
    } SignatureSchemeList;
    """
    def __init__(self, **kwargs):
        self.struct = Members(self, [
            Member(Listof(SignatureScheme), 'supported_signature_algorithms',
                   length_t=Uint16),
        ])
        self.struct.set_args(**kwargs)

    @classmethod
    def get_types_from_bytes(cls, data):
        reader = Reader(data)
        supported_signature_algorithms = reader.get(Listof(SignatureScheme), length_t=Uint16)
        return cls(supported_signature_algorithms=supported_signature_algorithms)
