# -*- coding: UTF-8 -*-
from .messages import Extension
from .signature import SignatureScheme
from ...utilization.bytestream import Reader
from ...utilization.type import Uint8, Uint16, Uint24, Type
from ...utilization.struct import Struct, Members, Member, Listof

__all__ = [
    'CertificateType', 'CertificateEntry', 'Certificate',
    'CertificateVerify', 'Finished', 'Hash',
]


@Type.add_labels_and_values
class CertificateType(Type):
    # 证书类型
    """
    enum {
          X509(0),
          RawPublicKey(2),
          (255)
      } CertificateType;
    """
    X509 = Uint8(0)
    OpenPGP_RESERVED = Uint8(1)
    RawPublicKey = Uint8(2)
    _size = 1


class CertificateEntry(Struct):
    # 证书内容
    """
    struct {
      select (certificate_type) {
        case RawPublicKey:
          /* From RFC 7250 ASN.1_subjectPublicKeyInfo */
          opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
        case X509:
          opaque cert_data<1..2^24-1>;
      };
      Extension extensions<0..2^16-1>;
    } CertificateEntry;
    """
    def __init__(self, **kwargs):
        self.struct = Members(self, [
            Member(bytes, 'cert_data', length_t=Uint24),
            Member(Listof(Extension), 'extensions', length_t=Uint16),
        ])
        self.struct.set_args(**kwargs)

    @classmethod
    def get_types_from_bytes(cls, data=b'', reader=None):
        is_given_reader = bool(reader)
        if not is_given_reader:
            reader = Reader(data)

        cert_data = reader.get(bytes, length_t=Uint24)
        extensions = reader.get(bytes, length_t=Uint16)

        # 输入扩展名的扩展名是status_request或signed_certificate_timestamp
        # 粘贴extensions字节的字节很麻烦而且不太重要，所以我会推迟它
        obj = cls(cert_data=cert_data, extensions=[])

        if is_given_reader:
            return (obj, reader)
        return obj


class Certificate(Struct):
    # 发送证书
    """
    struct {
      opaque certificate_request_context<0..2^8-1>;
      CertificateEntry certificate_list<0..2^24-1>;
    } Certificate;
    """
    def __init__(self, **kwargs):
        self.struct = Members(self, [
            Member(bytes, 'certificate_request_context', length_t=Uint8),
            Member(Listof(CertificateEntry), 'certificate_list', length_t=Uint24),
        ])
        self.struct.set_default('certificate_request_context', b'')
        self.struct.set_args(**kwargs)

    @classmethod
    def get_types_from_bytes(cls, data):
        reader = Reader(data)
        certificate_request_context = reader.get(bytes, length_t=Uint8)
        certificate_list_bytes = reader.get(bytes, length_t=Uint24)
        certificate_list = []

        reader = Reader(certificate_list_bytes)
        while reader.get_rest_length() > 0:
            entry, reader = CertificateEntry.get_types_from_bytes(reader=reader)
            certificate_list.append(entry)

        return cls(certificate_request_context=certificate_request_context,
                   certificate_list=certificate_list)


class CertificateVerify(Struct):
    # 发送证书签名
    """
    struct {
      SignatureScheme algorithm;
      opaque signature<0..2^16-1>;
    } CertificateVerify;
    """
    def __init__(self, **kwargs):
        self.struct = Members(self, [
            Member(SignatureScheme, 'algorithm'),
            Member(bytes, 'signature', length_t=Uint16),
        ])
        self.struct.set_args(**kwargs)

    @classmethod
    def get_types_from_bytes(cls, data):
        reader = Reader(data)
        algorithm = reader.get(Uint16)
        signature = reader.get(bytes, length_t=Uint16)
        return cls(algorithm=algorithm, signature=signature)


class Hash(bytes):
    size = 32

    @classmethod
    def set_size(cls, size):
        cls.size = size


class Finished(Struct):
    # 发送完成TLS握手
    """
    struct {
      opaque verify_data[Hash.length];
    } Finished;
    """
    def __init__(self, **kwargs):
        self.struct = Members(self, [
            Member(Hash, 'verify_data'),
        ])
        self.struct.set_args(**kwargs)

    @classmethod
    def get_types_from_bytes(cls, data):
        reader = Reader(data)
        verify_data = reader.get(Hash)
        return cls(verify_data=verify_data)

