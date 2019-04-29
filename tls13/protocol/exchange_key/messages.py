# -*- coding: UTF-8 -*-
import sys
import secrets
import collections
from .supportedgroups import NamedGroup
from .tls_version import ProtocolVersion
from ..ciphersuite import CipherSuite
from ..handshake import HandshakeType
from ...utilization import Uint32, Uint8, Uint16, Type, Reader
from ...utilization.struct import Struct, Members, Member, Listof

__all__ = [
    'ClientHello', 'ServerHello', 'Extension', 'ExtensionType',
    'KeyShareEntry', 'KeyShareClientHello', 'KeyShareHelloRetryRequest',
    'KeyShareServerHello', 'UncompressedPointRepresentation',
    'PskKeyExchangeMode', 'PskKeyExchangeModes', 'Empty', 'EarlyDataIndication',
    'PskIdentity', 'OfferedPsks', 'PreSharedKeyExtension'
]


def find(lst, cond):
    assert isinstance(lst, collections.Iterable)
    return next((x for x in lst if cond(x)), None)


class Random(bytes):
    """ opaque Random[32]; """
    _size = 32


class HasExtension:
    """
    Mixin class HasExtension implements common operation about extension.
    """
    def get_extension(self, extension_type):
        assert extension_type in ExtensionType.values
        ext = find(self.extensions, lambda ext: ext.extension_type == extension_type)
        return getattr(ext, 'extension_data', None)


class EncryptedExtensions(Struct):
    def __init__(self, **kwargs):
        self.struct = Members(self, [
            Member(bytes, 'encrypted_extension_data')
        ])
        self.struct.set_args(**kwargs)

    @classmethod
    def get_types_from_bytes(cls, data):
        reader = Reader(data)
        last_data = reader.get_rest()
        return cls(encrypted_extension_data=last_data)


class ClientHello(Struct, HasExtension):
    """
    struct {
      ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
      Random random;
      opaque legacy_session_id<0..32>;
      CipherSuite cipher_suites<2..2^16-2>;
      opaque legacy_compression_methods<1..2^8-1>;
      Extension extensions<8..2^16-1>;
    } ClientHello;
    """
    def __init__(self, **kwargs):
        self.struct = Members(self, [
            Member(ProtocolVersion, 'legacy_version'),
            Member(Random, 'random'),
            Member(bytes, 'legacy_session_id', length_t=Uint8),
            Member(Listof(CipherSuite), 'cipher_suites', length_t=Uint16),
            Member(Listof(Uint8), 'legacy_compression_methods', length_t=Uint8),
            Member(Listof(Extension), 'extensions', length_t=Uint16),
        ])
        self.struct.set_default('legacy_version', Uint16(0x0303))
        self.struct.set_default('random', secrets.token_bytes(32))
        self.struct.set_default('legacy_session_id', secrets.token_bytes(32))
        self.struct.set_default('legacy_compression_methods', [Uint8(0x00)])
        self.struct.set_args(**kwargs)

    @classmethod
    def get_types_from_bytes(cls, data):
        from ..handshake import HandshakeType
        reader = Reader(data)
        legacy_version = reader.get(Uint16)
        random = reader.get(Random)
        legacy_session_id = reader.get(bytes, length_t=Uint8)
        cipher_suites = reader.get(Listof(CipherSuite), length_t=Uint16)
        legacy_compression_methods = reader.get(Listof(Uint8), length_t=Uint8)

        # Read extensions
        extensions = Extension.get_list_from_bytes(
            reader.get_rest(),
            msg_type=HandshakeType.client_hello)

        return cls(legacy_version=legacy_version,
                   random=random,
                   legacy_session_id=legacy_session_id,
                   cipher_suites=cipher_suites,
                   extensions=extensions)


class ServerHello(Struct, HasExtension):
    """
    struct {
      ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
      Random random;
      opaque legacy_session_id_echo<0..32>;
      CipherSuite cipher_suite;
      Uint8 legacy_compression_method = 0;
      Extension extensions<6..2^16-1>;
    } ServerHello;
    """
    def __init__(self, **kwargs):
        self.struct = Members(self, [
            Member(ProtocolVersion, 'legacy_version'),
            Member(Random, 'random'),
            Member(bytes, 'legacy_session_id_echo', length_t=Uint8),
            Member(CipherSuite, 'cipher_suite'),
            Member(Uint8, 'legacy_compression_method'),
            Member(Listof(Extension), 'extensions', length_t=Uint16),
        ])
        self.struct.set_default('legacy_version', Uint16(0x0303))
        self.struct.set_default('random', secrets.token_bytes(32))
        self.struct.set_default('legacy_session_id_echo', secrets.token_bytes(32))
        self.struct.set_default('legacy_compression_method', Uint8(0x00))
        self.struct.set_args(**kwargs)

    @classmethod
    def get_types_from_bytes(cls, data):
        from ..handshake import HandshakeType
        reader = Reader(data)
        legacy_version = reader.get(Uint16)
        random = reader.get(Random)
        legacy_session_id_echo = reader.get(bytes, length_t=Uint8)
        cipher_suite = reader.get(Uint16)
        legacy_compression_methods = reader.get(Uint8)

        # Read extensions
        extensions = Extension.get_list_from_bytes(
            reader.get_rest(),
            msg_type=HandshakeType.server_hello)

        return cls(legacy_version=legacy_version,
                   random=random,
                   legacy_session_id_echo=legacy_session_id_echo,
                   cipher_suite=cipher_suite,
                   extensions=extensions)


class Extension(Struct):
    """
    struct {
      ExtensionType extension_type;
      opaque extension_data<0..2^16-1>;
    } Extension;
    """
    def __init__(self, **kwargs):
        self.struct = Members(self, [
            Member(ExtensionType, 'extension_type'),
            Member(Struct, 'extension_data', length_t=Uint16),
        ])
        self.struct.set_args(**kwargs)

    @classmethod
    def get_types_from_bytes(cls, data=b'', msg_type=None, reader=None):
        is_given_reader = bool(reader)
        if not is_given_reader:
            reader = Reader(data)

        extension_type = reader.get(Uint16)
        extension_data = reader.get(bytes, length_t=Uint16)

        ExtClass, kwargs = cls.get_extension_class(extension_type, msg_type)
        if ExtClass is None:
            obj = None
        else:
            obj = cls(
                extension_type=extension_type,
                extension_data=ExtClass.get_types_from_bytes(extension_data, **kwargs))

        if is_given_reader:
            return (obj, reader)
        return obj

    # 从字节序列重建时返回数组中每个扩展的函数。
    # 在每个消息中，如ClientHello和ServerHello，都有多个扩展，
    # 每个扩展的字节长度不同，因此实现并不像其他from_bytes那样容易。
    @classmethod
    def get_list_from_bytes(cls, data, msg_type=None):
        reader = Reader(data)
        extensions = []
        extensions_length = reader.get(2)
        assert extensions_length == reader.get_rest_length()

        # Read extensions
        while reader.get_rest_length() != 0:
            ext, reader = cls.get_types_from_bytes(reader=reader, msg_type=msg_type)
            if ext is None: continue
            extensions.append(ext)

        return extensions

    # 返回类ExtClass和kwargs，用于从扩展类型extension_type构造它。
    # 对于字典类型kwargs，当ExtClass.from_bytes完成时进行通信
    # 如果需要将其赋予参数，请在kwargs中返回必需的参数。
    # 为client_hello或server_hello的某些类的结构内容发生了变化，
    # 可能需要设置通信的参数msg_type。
    # 如果需要，但没有设置问题msg_type，请发出RuntimeError。
    @classmethod
    def get_extension_class(self, extension_type, msg_type=None):
        from ..handshake import HandshakeType
        from .tls_version import SupportedVersions
        from .supportedgroups import NamedGroupList
        from .signature import SignatureSchemeList

        ExtClass = None
        kwargs = {}

        if extension_type == ExtensionType.supported_versions:
            if msg_type is None:
                raise RuntimeError("must be set msg_type to get_extension_class()")
            ExtClass = SupportedVersions
            kwargs = {'msg_type': msg_type}

        elif extension_type == ExtensionType.supported_groups:
            ExtClass = NamedGroupList

        elif extension_type == ExtensionType.signature_algorithms:
            ExtClass = SignatureSchemeList

        elif extension_type == ExtensionType.key_share:
            if msg_type == HandshakeType.client_hello:
                ExtClass = KeyShareClientHello
            elif msg_type == HandshakeType.server_hello:
                ExtClass = KeyShareServerHello
            else:
                raise RuntimeError("must be set msg_type to get_extension_class()")

        else:
            output = 'Extension: unknown extension: %s' % extension_type
            if extension_type in ExtensionType.labels:
                output += ' == %s' % ExtensionType.labels[extension_type]
            print(output, file=sys.stdout)
            return (None, None)

        return (ExtClass, kwargs)


@Type.add_labels_and_values
class ExtensionType(Type):
    """
    enum {
        server_name(0),                             /* RFC 6066 */
        max_fragment_length(1),                     /* RFC 6066 */
        status_request(5),                          /* RFC 6066 */
        supported_groups(10),                       /* RFC 8422, 7919 */
        signature_algorithms(13),                   /* RFC 8446 */
        use_srtp(14),                               /* RFC 5764 */
        heartbeat(15),                              /* RFC 6520 */
        application_layer_protocol_negotiation(16), /* RFC 7301 */
        signed_certificate_timestamp(18),           /* RFC 6962 */
        client_certificate_type(19),                /* RFC 7250 */
        server_certificate_type(20),                /* RFC 7250 */
        padding(21),                                /* RFC 7685 */
        pre_shared_key(41),                         /* RFC 8446 */
        early_data(42),                             /* RFC 8446 */
        supported_versions(43),                     /* RFC 8446 */
        cookie(44),                                 /* RFC 8446 */
        psk_key_exchange_modes(45),                 /* RFC 8446 */
        certificate_authorities(47),                /* RFC 8446 */
        oid_filters(48),                            /* RFC 8446 */
        post_handshake_auth(49),                    /* RFC 8446 */
        signature_algorithms_cert(50),              /* RFC 8446 */
        key_share(51),                              /* RFC 8446 */
        (65535)
    } ExtensionType;
    """
    server_name = Uint16(0)
    max_fragment_length = Uint16(1)
    status_request = Uint16(5)
    supported_groups = Uint16(10)
    signature_algorithms = Uint16(13)
    use_srtp = Uint16(14)
    heartbeat = Uint16(15)
    application_layer_protocol_negotiation = Uint16(16)
    signed_certificate_timestamp = Uint16(18)
    client_certificate_type = Uint16(19)
    server_certificate_type = Uint16(20)
    padding = Uint16(21)
    pre_shared_key = Uint16(41)
    early_data = Uint16(42)
    supported_versions = Uint16(43)
    cookie = Uint16(44)
    psk_key_exchange_modes = Uint16(45)
    certificate_authorities = Uint16(47)
    oid_filters = Uint16(48)
    post_handshake_auth = Uint16(49)
    signature_algorithms_cert = Uint16(50)
    key_share = Uint16(51)
    _size = 2


class KeyShareEntry(Struct):
    """
    struct {
      NamedGroup group;
      opaque key_exchange<1..2^16-1>;
    } KeyShareEntry;
    """
    def __init__(self, **kwargs):
        self.struct = Members(self, [
            Member(NamedGroup, 'group'),
            Member(bytes, 'key_exchange', length_t=Uint16),
        ])
        self.struct.set_args(**kwargs)

    @classmethod
    def get_types_from_bytes(cls, data=b'', reader=None):
        is_given_reader = bool(reader)
        if not is_given_reader:
            reader = Reader(data)

        group = reader.get(Uint16)
        key_exchange = reader.get(bytes, length_t=Uint16)
        object = cls(group=group, key_exchange=key_exchange)

        if is_given_reader:
            return (object, reader)
        return object


class KeyShareClientHello(Struct):
    """
    struct {
      KeyShareEntry client_shares<0..2^16-1>;
    } KeyShareClientHello;
    """
    def __init__(self, **kwargs):
        self.struct = Members(self, [
            Member(Listof(KeyShareEntry), 'client_shares', length_t=Uint16),
        ])
        self.struct.set_args(**kwargs)

    @classmethod
    def get_types_from_bytes(cls, data):
        reader = Reader(data)

        # Read client_shares
        client_shares = []
        client_shares_length = reader.get(2)
        assert client_shares_length == reader.get_rest_length()

        while reader.get_rest_length() != 0:
            entry, reader = KeyShareEntry.get_types_from_bytes(reader=reader)
            client_shares.append(entry)

        return cls(client_shares=client_shares)

    def get_groups(self):
        return [client_share.group for client_share in self.client_shares]

    def get_key_exchange(self, group):
        assert group in NamedGroup.values
        cs = find(self.client_shares, lambda cs: cs.group == group)
        return getattr(cs, 'key_exchange', None)


class KeyShareHelloRetryRequest(Struct):
    """
    struct {
      NamedGroup selected_group;
    } KeyShareHelloRetryRequest;
    """
    def __init__(self, selected_group):
        self.selected_group = selected_group
        assert self.selected_group in NamedGroup.values


class KeyShareServerHello(Struct):
    """
    struct {
      KeyShareEntry server_share;
    } KeyShareServerHello;
    """
    def __init__(self, server_share):
        self.server_share = server_share
        assert type(self.server_share) == KeyShareEntry

        self.struct = Members(self, [
            Member(KeyShareEntry, 'server_share'),
        ])

    @classmethod
    def get_types_from_bytes(cls, data):
        return cls(server_share=KeyShareEntry.get_types_from_bytes(data))

    def get_group(self):
        return self.server_share.group

    def get_key_exchange(self):
        return self.server_share.key_exchange


class UncompressedPointRepresentation:
    """
    struct {
      Uint8 legacy_form = 4;
      opaque X[coordinate_length];
      opaque Y[coordinate_length];
    } UncompressedPointRepresentation;
    """


@Type.add_labels_and_values
class PskKeyExchangeMode(Type):
    """
    enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;
    """
    psk_ke = Uint8(0)
    psk_dhe_ke = Uint8(1)
    _size = 1


class PskKeyExchangeModes:
    """
    struct {
      PskKeyExchangeMode ke_modes<1..255>;
    } PskKeyExchangeModes;
    """
    def __init__(self, ke_modes=[]):
        self.ke_modes = ke_modes


class Empty:
    """
    struct {} Empty;
    """
    pass


class EarlyDataIndication:
    """
    struct {
      select (Handshake.msg_type) {
        case new_session_ticket:   Uint32 max_early_data_size;
        case client_hello:         Empty;
        case encrypted_extensions: Empty;
      };
    } EarlyDataIndication;
    """
    def __init__(self, msg_type, max_early_data_size=Empty()):
        assert msg_type in HandshakeType.values
        self.msg_type = msg_type
        self.max_early_data_size = max_early_data_size
        if msg_type == HandshakeType.new_session_ticket:
            assert type(max_early_data_size) == Uint32


class PskIdentity:
    """
    struct {
      opaque identity<1..2^16-1>;
      Uint32 obfuscated_ticket_age;
    } PskIdentity;
    """
    pass


class OfferedPsks:
    """
    struct {
      PskIdentity identities<7..2^16-1>;
      PskBinderEntry binders<33..2^16-1>;
    } OfferedPsks;
    """
    pass


class PreSharedKeyExtension:
    """
    struct {
      select (Handshake.msg_type) {
        case client_hello: OfferedPsks;
        case server_hello: Uint16 selected_identity;
      };
    } PreSharedKeyExtension;
    """
    pass
