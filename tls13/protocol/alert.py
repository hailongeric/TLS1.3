# -*- coding: UTF-8 -*-
from ..utilization.type import Uint8, Type
from ..utilization.bytestream import Reader
from ..utilization.struct import Struct, Members, Member

__all__ = [
    'AlertLevel', 'AlertDescription', 'Alert',
]


@Type.add_labels_and_values
class AlertLevel(Type):
    """
    enum { warning(1), fatal(2), (255) } AlertLevel;
    """
    warning = Uint8(1)
    fatal = Uint8(2)
    _size = 1  # byte


@Type.add_labels_and_values
class AlertDescription(Type):
    """
    enum {
          close_notify(0),
          unexpected_message(10),
          bad_record_mac(20),
          record_overflow(22),
          handshake_failure(40),
          bad_certificate(42),
          unsupported_certificate(43),
          certificate_revoked(44),
          certificate_expired(45),
          certificate_unknown(46),
          illegal_parameter(47),
          unknown_ca(48),
          access_denied(49),
          decode_error(50),
          decrypt_error(51),
          protocol_version(70),
          insufficient_security(71),
          internal_error(80),
          inappropriate_fallback(86),
          user_canceled(90),
          missing_extension(109),
          unsupported_extension(110),
          unrecognized_name(112),
          bad_certificate_status_response(113),
          unknown_psk_identity(115),
          certificate_required(116),
          no_application_protocol(120),
          (255)
      } AlertDescription;
    """
    close_notify = Uint8(0)
    unexpected_message = Uint8(10)
    bad_record_mac = Uint8(20)
    decryption_failed_RESERVED = Uint8(21)
    record_overflow = Uint8(22)
    decompression_failure_RESERVED = Uint8(30)
    handshake_failure = Uint8(40)
    no_certificate_RESERVED = Uint8(41)
    bad_certificate = Uint8(42)
    unsupported_certificate = Uint8(43)
    certificate_revoked = Uint8(44)
    certificate_expired = Uint8(45)
    certificate_unknown = Uint8(46)
    illegal_parameter = Uint8(47)
    unknown_ca = Uint8(48)
    access_denied = Uint8(49)
    decode_error = Uint8(50)
    decrypt_error = Uint8(51)
    export_restriction_RESERVED = Uint8(60)
    protocol_version = Uint8(70)
    insufficient_security = Uint8(71)
    internal_error = Uint8(80)
    inappropriate_fallback = Uint8(86)
    user_canceled = Uint8(90)
    no_renegotiation_RESERVED = Uint8(100)
    missing_extension = Uint8(109)
    unsupported_extension = Uint8(110)
    certificate_unobtainable = Uint8(111)
    unrecognized_name = Uint8(112)
    bad_certificate_status_response = Uint8(113)
    bad_certificate_hash_value = Uint8(114)
    unknown_psk_identity = Uint8(115)
    certificate_required = Uint8(116)
    no_application_protocol = Uint8(120)
    _size = 1  # _size


class Alert(Struct):
    # 用于在传输内容出错时发送警告
    """
    struct {
      AlertLevel level;
      AlertDescription description;
    } Alert;
    """
    def __init__(self, **kwargs):
        self.struct = Members(self, [
            Member(AlertLevel, 'level'),
            Member(AlertDescription, 'description'),
        ])
        self.struct.set_args(**kwargs)

    @classmethod
    def get_types_from_bytes(cls, data):
        reader = Reader(data)
        level = reader.get(Uint8)
        description = reader.get(Uint8)
        return cls(level=level, description=description)
