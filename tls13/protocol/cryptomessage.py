# -*- coding: UTF-8 -*-
import struct
from .exchange_key.tls_version import ProtocolVersion
from .alert import Alert
from ..utilization.type import Uint8, Uint16, Type
from ..utilization.bytestream import Reader
from ..utilization.struct import Struct, Members, Member

__all__ = [
    'ContentType', 'TLSPlaintext', 'TLSInnerPlaintext', 'TLSCiphertext',
    'Data', 'TLSRawtext',
]


@Type.add_labels_and_values
class ContentType(Type):
    """
    enum {
          invalid(0),
          change_cipher_spec(20),
          alert(21),
          handshake(22),
          application_data(23),
          heartbeat(24),  /* RFC 6520 */
          (255)
      } ContentType;
    """
    invalid = Uint8(0)
    change_cipher_spec = Uint8(20)
    alert = Uint8(21)
    handshake = Uint8(22)
    application_data = Uint8(23)
    heartbeat = Uint8(24)
    _size = 1


class TLSPlaintext(Struct):
    """
    struct {
      ContentType type;
      ProtocolVersion legacy_record_version;
      Uint16 length;
      opaque fragment[TLSPlaintext.length];
    } TLSPlaintext;
    """
    def __init__(self, **kwargs):
        fragment = kwargs.get('fragment', b'')
        self.struct = Members(self, [
            Member(ContentType, 'type'),
            Member(ProtocolVersion, 'legacy_record_version'),
            Member(Uint16, 'length'),
            Member(Struct, 'fragment'),
        ])
        self.struct.set_default('legacy_record_version', Uint16(0x0303))
        self.struct.set_default('length', Uint16(len(fragment)))
        self.struct.set_args(**kwargs)

    def __getattr__(self, name):
        """
        返回self.fragment.msg的命名属性的值。
         在这个类中，self表示记录层，self.fragment表示握手层，
         记录层和握手层是区分通信类型所必需的，
         由于用于密钥共享等的所有数据组都在握手层之上的ClientHello和ServerHello中，
         而不是self.fragment.msg.foobar，使用self.foobar可以轻松访问。
        """
        if self.fragment is None or self.fragment.msg is None:
            raise AttributeError("'%s' object has no attribute '%s'" % (self.__class__.__name__, name))
        return getattr(self.fragment.msg, name)

    @classmethod
    def get_types_from_bytes(cls, data, mode=None):
        from .handshake import Handshake
        reader = Reader(data)
        type = reader.get(Uint8)
        legacy_record_version = reader.get(Uint16)
        fragment = reader.get(bytes, length_t=Uint16)
        length = Uint16(len(fragment))

        if mode:
            type = mode  # 注 mode=ContentType.handshake

        if type == ContentType.handshake:
            return cls(type=type, fragment=Handshake.get_types_from_bytes(fragment))
        elif type == ContentType.application_data:
            return cls(type=type, fragment=Data(fragment))
        elif type == ContentType.alert:
            return cls(type=type, fragment=Alert.get_types_from_bytes(fragment))
        else:
            raise NotImplementedError()


class Data(Struct):
    # TLSPlaintext.fragment包含一个TLS结构和要发送的数据，但是成员，
    #      因为它被写为Member（Struct，'fragment'），所以它只接受Struct
    #      ，并将要发送到片段的数据（字节字符串）导致错误。
    #      所以创建一个名为Data的类，它继承了Struct。
    def __init__(self, data):
        self.data = data

    def __repr__(self):
        return self.data.decode('utf-8')

    def __len__(self):
        return len(self.data)

    def hex(self):
        return self.data.hex()

    def to_bytes(self):
        return self.data

    @classmethod
    def get_types_from_bytes(self, data):
        return data


class TLSInnerPlaintext(Struct):
    """
    struct {
      opaque content[TLSPlaintext.length];
      ContentType type;
      Uint8 zeros[length_of_padding];
    } TLSInnerPlaintext;
    """
    def __init__(self, content, type, length_of_padding):
        self.content = content  # TLSPlaintext.fragment
        self.type = type
        self.zeros = b'\x00' * length_of_padding
        self._length_of_padding = length_of_padding

        self.struct = Members(self, [
            Member(bytes, 'content'),
            Member(ContentType, 'type'),
            Member(bytes, 'zeros'),
        ])

    @classmethod
    def get_types_from_bytes(cls, data):
        content, type, zeros = cls.split_pad(data)
        return cls(content=content, type=type, length_of_padding=len(zeros))

    @staticmethod
    def split_pad(data):
        for pos, value in zip(reversed(range(len(data))), reversed(data)):
            if value != 0:
                break
        return (data[:pos], Uint8(value), data[pos + 1:]) # content, type, zeros

    @classmethod
    def create(cls, tlsplaintext, length_of_padding=None):
        if length_of_padding is None:
            # 根据不同的加密方式，块的大小也不同
            # length_of_padding = 64 - len(tlsplaintext) % 64
            length_of_padding = 16 - len(tlsplaintext.fragment) % 16 - 1
        return cls(
            content=tlsplaintext.fragment.to_bytes(),
            type=tlsplaintext.type,
            length_of_padding=length_of_padding)

    @classmethod
    def restore(cls,tlsciphertext):
        # print(type(tlsciphertext.content))
        # print(type(b'\x03\x03'))
        context = tlsciphertext.type.to_bytes() + b'\x03\x03' + struct.pack('>H', (len(tlsciphertext.content))) + tlsciphertext.content

        return context


class TLSCiphertext(Struct):
    """
    struct {
      ContentType opaque_type = application_data; /* 23 */
      ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
      Uint16 length;
      opaque encrypted_record[TLSCiphertext.length];
    } TLSCiphertext;
    """
    def __init__(self, **kwargs):
        encrypted_record = kwargs.get('encrypted_record', b'')
        self.struct = Members(self, [
            Member(ContentType, 'opaque_type'),
            Member(ProtocolVersion, 'legacy_record_version'),
            Member(Uint16, 'length'),
            Member(bytes, 'encrypted_record'),
        ])
        self.struct.set_default('opaque_type', ContentType.application_data)
        self.struct.set_default('legacy_record_version', ProtocolVersion.TLS12)
        self.struct.set_default('length', Uint16(len(encrypted_record)))
        self.struct.set_args(**kwargs)

    @classmethod
    def get_types_from_bytes(cls, data):
        reader = Reader(data)
        opaque_type = reader.get(Uint8)
        legacy_record_version = reader.get(Uint16)
        encrypted_record = reader.get(bytes, length_t=Uint16)
        length = Uint16(len(encrypted_record))
        return cls(length=length, encrypted_record=encrypted_record)


    '''
     The record protection functions translate a TLSPlaintext structure
   into a TLSCiphertext structure.  The deprotection functions reverse
   the process.  In TLS 1.3, as opposed to previous versions of TLS, all
   ciphers are modeled as "Authenticated Encryption with Associated
   Data" (AEAD) [RFC5116].  AEAD functions provide a unified encryption
   and authentication operation which turns plaintext into authenticated
   ciphertext and back again.  Each encrypted record consists of a
   plaintext header followed by an encrypted body, which itself contains
   a type and optional padding.

      struct {
          opaque content[TLSPlaintext.length];
          ContentType type;
          uint8 zeros[length_of_padding];
      } TLSInnerPlaintext;

      struct {
          ContentType opaque_type = application_data; /* 23 */
          ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
          uint16 length;
          opaque encrypted_record[TLSCiphertext.length];
      } TLSCiphertext;

   content:  The TLSPlaintext.fragment value, containing the byte
      encoding of a handshake or an alert message, or the raw bytes of
      the application's data to send.

   type:  The TLSPlaintext.type value containing the content type of the
      record.

   zeros:  An arbitrary-length run of zero-valued bytes may appear in
      the cleartext after the type field.  This provides an opportunity
      for senders to pad any TLS record by a chosen amount as long as
      the total stays within record size limits.  See Section 5.4 for
      more details.

    '''


    @classmethod
    def create(cls, tlsplaintext, crypto):
        # 从TLSPlaintext处理到创建TLSCiphertext
        # print(tlsplaintext)
        app_data_inner = TLSInnerPlaintext.create(tlsplaintext)

        # additional_data =
        #   TLSCiphertext.opaque_type || .legacy_record_version || .length
        # print("11111111111111")
        # print(app_data_inner)
        length = len(crypto.encrypt(app_data_inner.to_bytes(), nonce=crypto.iv)) + 16
        # print("[+] length:", length)
        aad = b'\x17\x03\x03' + Uint16(length).to_bytes()
        # print('[+] AAD:', aad.hex())
        # print("Hailongg12344")
        # print(app_data_inner)
        encrypted_record = crypto.aead_encrypt(aad, app_data_inner.to_bytes())
        # print('[+] encrypted_record:')
        # print(encrypted_record.hex())
        app_data_cipher = TLSCiphertext(encrypted_record=encrypted_record)
        return app_data_cipher

    @classmethod
    def restore(cls, data, crypto, mode=None) -> TLSPlaintext:
        recved_app_data_cipher = TLSCiphertext.get_types_from_bytes(data)
        length = recved_app_data_cipher.length.value
        # print("[+] length:", length)
        aad = b'\x17\x03\x03' + Uint16(length).to_bytes()
        # print('[+] AAD:', aad.hex())

        # 确定长度是否为警报
        if length == 2:
            # print("[-] Alert!")
            print(TLSPlaintext.get_types_from_bytes(data))
            raise RuntimeError("Alert!")

        print("\nrestore before:", recved_app_data_cipher.encrypted_record.hex())
        recved_app_data_inner_bytes = crypto.aead_decrypt(aad, recved_app_data_cipher.encrypted_record)
        if recved_app_data_inner_bytes is None:
            raise RuntimeError('aead_decrypt Error')
        print("\nrestore after:")
        print(recved_app_data_inner_bytes)
        print()
        # print(hexdump(recved_app_data_inner_bytes))
        if mode == ContentType.application_data:
            content, type, zeros = TLSInnerPlaintext.split_pad(recved_app_data_inner_bytes)
            print("content, type, zeros: ", content, type, zeros)
            return TLSRawtext(raw=content)

        recved_app_data_inner = TLSInnerPlaintext.get_types_from_bytes(recved_app_data_inner_bytes)
        recved_app_data_inner = TLSInnerPlaintext.restore(recved_app_data_inner)
        # content = Uint8(recved_app_data_inner.type).to_bytes() + b'\x03\03' + Uint16(int(len(content))).to_bytes() + content
        recved_app_data = TLSPlaintext.get_types_from_bytes(recved_app_data_inner, mode=mode)

        return recved_app_data


class TLSRawtext(Struct):
    """
    struct {
      ContentType opaque_type = application_data; /* 23 */
      ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
      Uint16 length;
      opaque raw[TLSCiphertext.length];
    } TLSCiphertext;
    """
    def __init__(self, **kwargs):
        self.struct = Members(self, [
            Member(ContentType, 'opaque_type'),
            Member(ProtocolVersion, 'legacy_record_version'),
            Member(bytes, 'raw', length_t=Uint16),
        ])
        self.struct.set_default('opaque_type', ContentType.application_data)
        self.struct.set_default('legacy_record_version', ProtocolVersion.TLS12)
        self.struct.set_args(**kwargs)

    @classmethod
    def get_types_from_bytes(cls, data):
        reader = Reader(data)
        opaque_type = reader.get(Uint8)
        legacy_record_version = reader.get(Uint16)
        raw = reader.get(bytes, length_t=Uint16)
        return cls(raw=raw)
