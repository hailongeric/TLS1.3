# -*- coding: UTF-8 -*-
from .exchange_key.messages import Extension
from ..utilization.struct import Struct, Members, Member, Listof
from ..utilization.type import Uint8, Uint16, Uint32


class NewSessionTicket(Struct):
    """
    struct {
      Uint32 ticket_lifetime;
      Uint32 ticket_age_add;
      opaque ticket_nonce<0..255>;
      opaque ticket<1..2^16-1>;
      Extension extensions<0..2^16-2>;
    } NewSessionTicket;
    """
    def __init__(self, **kwargs):
        self.struct = Members(self, [
            Member(Uint32, 'ticket_lifetime'),
            Member(Uint32, 'ticket_age_add'),
            Member(bytes, 'ticket_nonce', length_t=Uint8),
            Member(bytes, 'ticket', length_t=Uint16),
            Member(Listof(Extension), 'extensions', length_t=Uint16),
        ])
        self.struct.set_args(**kwargs)
