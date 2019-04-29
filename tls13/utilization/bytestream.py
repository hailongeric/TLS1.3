# -*- coding: UTF-8 -*-
from typing import List
from .type import Uint, Type

__all__ = ['Reader', 'Writer']


class ReaderParseError(Exception):
    pass


class Reader:
    """
    Byte string reader
    """
    def __init__(self, data):
        self.bytes = data
        self.index = 0

    def get(self, type, length_t=None) -> int or Uint:
        from .struct import Listof, Struct

        if isinstance(type, int):
            return self.get_int(type)

        if isinstance(type, Listof):
            elem_len = type.subtype._size
            length_len = length_t._size
            fun = lambda x: x
            # Listof(Type) 将列表的元素转换为 UintN
            if issubclass(type.subtype, (Uint, Type)):
                fun = Uint.get_type(type.subtype._size)
            return [fun(x) for x in self.get_var_list(elem_len, length_len)]

        if issubclass(type, Uint):
            return self.get_uint(type)

        if issubclass(type, (bytes, Struct)):
            if hasattr(type, '_size'):
                # print(type._size)
                return self.get_fix_bytes(type._size)
            if length_t:
                return self.get_var_bytes(length_t._size)
            return self.get_rest()

        raise NotImplementedError()

    def get_int(self, length) -> int:
        """
        Read a single big-endian integer value in 'length' bytes.
        """
        if self.index + length > len(self.bytes):
            raise ReaderParseError()
        x = 0
        for _ in range(length):
            x <<= 8
            x |= self.bytes[self.index]
            self.index += 1
        return x

    def get_uint(self, uint) -> Uint:
        length = uint._size
        x = self.get_int(length)
        return uint(x)

    def get_fix_bytes(self, bytes_length) -> bytearray:
        """
        Read a string of bytes encoded in 'bytes_length' bytes.
        """
        if self.index + bytes_length > len(self.bytes):
            raise ReaderParseError()
        bytes = self.bytes[self.index: self.index+bytes_length]
        self.index += bytes_length
        return bytes

    def get_var_bytes(self, length_length) -> bytearray:
        """
        Read a variable length string with a fixed length.
        """
        bytes_length = self.get(length_length)
        return self.get_fix_bytes(bytes_length)

    def get_fix_list(self, elem_length, list_length) -> List[int]:
        """
        Read a list of static length with same-sized ints.
        """
        l = [0] * list_length
        for x in range(list_length):
            l[x] = self.get(elem_length)
        return l

    def get_var_list(self, elem_length, length_length) -> List[int]:
        """
        Read a variable length list of same-sized integers.
        """
        list_length = self.get(length_length)
        if list_length % elem_length != 0:
            raise SyntaxError()
        list_length = list_length // elem_length
        l = [0] * list_length
        for x in range(list_length):
            l[x] = self.get(elem_length)
        return l

    def get_uint_var_list(self, elem, length_length):
        uint = elem
        elem_length = uint._size
        assert issubclass(uint, uint)
        return [uint(x) for x in self.get_var_list(elem_length, length_length)]

    def get_rest(self):
        """
        Read a rest of the data.
        """
        rest_bytes = self.bytes[self.index:]
        self.index = len(self.bytes)
        return rest_bytes

    def get_rest_length(self):
        return len(self.bytes) - self.index


class Writer:
    """
    Byte string writer
    """
    def __init__(self):
        self.bytes = bytearray(0)

    def _get_bytes(self, obj):
        if hasattr(obj, 'to_bytes') and callable(obj.to_bytes):
            return obj.to_bytes()
        else:
            return obj

    def add_bytes(self, obj, length_t=None):
        """
         一种将字节字符串添加到缓冲区的方法。
         缓冲区指的是self.bytes。
         如果参数obj中有.to_bytes（）方法，则在添加之前调用它并将其转换为字节字符串。
         参数length_t表示长度类型。 当给出诸如Uint 8，Uint 16等类型时，
         找到字节序列的长度，如果是Uint 16，则使其成为一个2字节的字节字符串，并在字节序列之前添加它。

         例如，如果要添加的字节字符串是b'abcdef'，长度类型是Uint 16，
         最终添加的字节序列如下。
        """
        if length_t:
            self.bytes += length_t(len(obj)).to_bytes()
        self.bytes += self._get_bytes(obj)

    def add_list(self, a_list, length_t):
        """
        将列表添加到缓冲区的方法。
        缓冲区指的是self.bytes。
        假设列表的所有元素都有.to_bytes（）方法。
        参数length_t表示长度类型。当给出诸如Uint8，Uint16等类型时，
        找到字节序列的长度，如果是Uint 16，则使其成为一个2字节的字节字符串，并在字节序列之前添加它。
        例如，如果要添加的列表是[Uint16（0x0304），Uint16（0x0303），Uint16（0x0302）]，
        当长度类型是Uint 16时，最后添加的字节序列如下。
             b'\ x00 \ x06 \ x03 \ x04 \ x03 \ x03 \ x03 \ x02'
        """
        self.bytes += length_t(sum(map(len, a_list))).to_bytes()
        self.bytes += b''.join(x.to_bytes() for x in a_list)
