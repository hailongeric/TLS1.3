# -*- coding: UTF-8 -*-
from ...utilization.type import Uint16, Type
from ...utilization.bytestream import Reader
from ...utilization.struct import Struct, Members, Member, Listof

__all__ = ['NamedGroup', 'NamedGroupList']


@Type.add_labels_and_values
class NamedGroup(Type):
    # 密钥交换组
    """
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
    """
    # Elliptic Curve Groups (ECDHE)
    obsolete_RESERVED = (Uint16(0x0001), Uint16(0x0016))
    secp256r1 = Uint16(0x0017)
    secp384r1 = Uint16(0x0018)
    secp521r1 = Uint16(0x0019)
    obsolete_RESERVED = (Uint16(0x001A), Uint16(0x001C))
    x25519 = Uint16(0x001D)
    x448 = Uint16(0x001E)

    # Finite Field Groups (DHE)
    # https://tools.ietf.org/html/rfc7919#appendix-A
    ffdhe2048 = Uint16(0x0100)
    ffdhe3072 = Uint16(0x0101)
    ffdhe4096 = Uint16(0x0102)
    ffdhe6144 = Uint16(0x0103)
    ffdhe8192 = Uint16(0x0104)

    # Reserved Code Points
    ffdhe_private_use = (Uint16(0x01FC), Uint16(0x01FF))
    ecdhe_private_use = (Uint16(0xFE00), Uint16(0xFEFF))
    obsolete_RESERVED = (Uint16(0xFF01), Uint16(0xFF02))

    _size = 2 # byte


class NamedGroupList(Struct):
    # 用于指示支持的密钥交换组列表
    """
    struct {
      NamedGroup named_group_list<2..2^16-1>;
    } NamedGroupList;
    """
    def __init__(self, **kwargs):
        self.struct = Members(self, [
            Member(Listof(NamedGroup), 'named_group_list', length_t=Uint16)
        ])
        self.struct.set_args(**kwargs)

    @classmethod
    def get_types_from_bytes(cls, data):
        reader = Reader(data)
        named_group_list = reader.get(Listof(NamedGroup), length_t=Uint16)
        return cls(named_group_list=named_group_list)
