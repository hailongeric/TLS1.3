# -*- coding: UTF-8 -*-
from ..utilization.type import Uint8, Uint16, Uint24, Type
from ..utilization.bytestream import Reader
from ..utilization.struct import Struct, Members, Member

__all__ = ['HandshakeType', 'Handshake']


@Type.add_labels_and_values
class HandshakeType(Type):
    """
    enum {
        client_hello(1),
        server_hello(2),
        new_session_ticket(4),
        end_of_early_data(5),
        encrypted_extensions(8),
        certificate(11),
        certificate_request(13),
        certificate_verify(15),
        finished(20),
        key_update(24),
        message_hash(254),
        (255)
    } HandshakeType;
    """
    client_hello = Uint8(1)
    server_hello = Uint8(2)
    new_session_ticket = Uint8(4)
    end_of_early_data = Uint8(5)
    encrypted_extensions = Uint8(8)
    certificate = Uint8(11)
    certificate_request = Uint8(13)
    certificate_verify = Uint8(15)
    finished = Uint8(20)
    key_update = Uint8(24)
    message_hash = Uint8(254)
    _size = 1


class Handshake(Struct):
    """
    struct {
      HandshakeType msg_type;    /* handshake type */
      Uint24 length;             /* bytes in message */
      select (Handshake.msg_type) {
        case client_hello:          ClientHello;
        case server_hello:          ServerHello;
        case end_of_early_data:     EndOfEarlyData;
        case encrypted_extensions:  EncryptedExtensions;
        case certificate_request:   CertificateRequest;
        case certificate:           Certificate;
        case certificate_verify:    CertificateVerify;
        case finished:              Finished;
        case new_session_ticket:    NewSessionTicket;
        case key_update:            KeyUpdate;
      };
    } Handshake;
    """
    def __init__(self, **kwargs):
        msg = kwargs.get('msg', b'')
        self.struct = Members(self, [
            Member(HandshakeType, 'msg_type'),
            Member(Uint24, 'length'),
            Member(Struct, 'msg'),
        ])
        self.struct.set_default('legacy_record_version', Uint16(0x0303))
        self.struct.set_default('length', Uint24(len(kwargs['msg'] or b'')))
        self.struct.set_args(**kwargs)

        assert self.msg_type in HandshakeType.values

    @classmethod
    def get_types_from_bytes(cls, data):
        from .exchange_key.messages import ClientHello, ServerHello, EncryptedExtensions
        from .exchange_key.authentication import Certificate, CertificateVerify, Finished
        reader = Reader(data)
        msg_type = reader.get(Uint8)
        length = reader.get(Uint24)
        msg = reader.get(bytes)

        assert length.value == len(msg)

        from_bytes_mapper = {
            HandshakeType.client_hello: ClientHello.get_types_from_bytes,
            HandshakeType.server_hello: ServerHello.get_types_from_bytes,
            HandshakeType.certificate: Certificate.get_types_from_bytes,
            HandshakeType.certificate_verify: CertificateVerify.get_types_from_bytes,
            HandshakeType.finished: Finished.get_types_from_bytes,
            HandshakeType.encrypted_extensions: EncryptedExtensions.get_types_from_bytes,
        }

        if msg_type not in from_bytes_mapper.keys():
            raise NotImplementedError()
        from_bytes = from_bytes_mapper[msg_type]
        return cls(msg_type=msg_type, msg=from_bytes(msg))
