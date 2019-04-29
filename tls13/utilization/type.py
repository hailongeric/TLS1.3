# -*- coding: UTF-8 -*-
from struct import pack

__all__ = [
    'Uint', 'Uint8', 'Uint16', 'Uint24', 'Uint32', 'Type',
]


class Uint:
    """
    base class
    """
    def __init__(self, value):
        assert type(value) is int
        # 应该从子类调用构造函数
        assert self.__class__ != Uint
        self.value = value

    def __repr__(self):
        return "{}(0x{:0{width}x})" .format(self.__class__.__name__, self.value, width=len(self)*2)

    def __len__(self):
        return self.__class__._size

    def __int__(self):
        return self.value

    # HACK:
    # 此类的实例用于以下两种方案：
    #   - 从常量获取标签名称：ContentType.labels[Uint8(22)]  #=> 'handshake'
    #   - 与常数比较：ContentType.handshake == Uint8(22)     #=> True
    # 为第二个实现__eq__方法将导致首次使用字典时出现类型错误
    # 「TypeError: unhashable type: Uint8」
    # 因此，创建一个__ hash__方法以避免错误。
    # 为了更严格地编写，有必要限制Uint8实例的属性.value不应该直接更改，
    # self.value需要是不可变的。
    # https://stackoverflow.com/questions/4996815/ways-to-make-a-class-immutable-in-python
    def __hash__(self):
        return hash((self.value,))

    def __eq__(self, other):
        return hasattr(other, 'value') and self.value == other.value

    @staticmethod
    def size(size):
        return Uint.get_type(size)

    @staticmethod
    def get_type(size):
        if size == 1:
            return Uint8
        if size == 2:
            return Uint16
        if size == 3:
            return Uint24
        if size == 4:
            return Uint32
        raise NotImplementedError()


class Uint8(Uint):
    """an unsigned byte"""
    _size = 1

    def to_bytes(self):
        return pack('>B', self.value)


class Uint16(Uint):
    """ Uint8 Uint24[2]; """
    _size = 2

    def to_bytes(self):
        return pack('>H', self.value)


class Uint24(Uint):
    """ Uint8 Uint24[3]; """
    _size = 3

    def to_bytes(self):
        return pack('>BH', self.value >> 16, self.value & 0xffff)


class Uint32(Uint):
    """ Uint8 Uint32[4]; """
    _size = 4

    def to_bytes(self):
        return pack('>I', self.value)


class Type:
    @staticmethod
    def add_labels_and_values(cls):
        """
        将标签和值字段添加到TLS中使用的常量组（枚举）。
         例如，当标签添加到HandshakeType时，可以从常量中获取常量名称，如下所示。
             HandshakeType.labels [Uint16（1）]＃=>'client_hello'
         此外，如果将值添加到HandshakeType，
         可以确认常数组中是否包含某个值。
            self.msg_type in HandshakeType.values # => True or False
        """
        UintN = Uint.get_type(cls._size)
        # add labels (inverted dict) to class
        # usage: HandshakeType.labels[Uint16(1)] # => 'client_hello'
        cls.labels = dict((v, k) for k, v in cls.__dict__.items())
        # add values to class
        # usage: assert self.msg_type in HandshakeType.values
        cls.values = set(v for k, v in cls.__dict__.items() if type(v) == UintN)
        return cls
