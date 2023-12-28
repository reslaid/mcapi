import logging
import os

import ctypes
import ctypes.util
import importlib.util


class CEncoding:
    def __init__(self) -> None:
        self._encoding = "utf-8"

    def encode_bytes(value: str, encoding: str = "utf-8"):
        return str(value).encode(encoding)
    
    def decode_bytes(value: bytes, encoding: str = "utf-8"):
        return bytes(value).decode(encoding)
    

class CTypes:
    def __init__(self) -> None:
        self._clang_types = {
            'short': ctypes.c_short,
            'ushort': ctypes.c_ushort,

            'int': ctypes.c_int,
            'int8': ctypes.c_int8,
            'int16': ctypes.c_int16,
            'int32': ctypes.c_int32,
            'int64': ctypes.c_int64,

            'uint': ctypes.c_uint,
            'uint8': ctypes.c_uint8,
            'uint16': ctypes.c_uint16,
            'uint32': ctypes.c_uint32,
            'uint64': ctypes.c_uint64,
            
            'long': ctypes.c_long,
            'dword': ctypes.c_ulong,
            'udword': ctypes.c_ulonglong,

            'float': ctypes.c_float,
            'double': ctypes.c_double,

            'size_t': ctypes.c_size_t,
            'ssize_t': ctypes.c_ssize_t,

            'char': ctypes.c_char,
            'wchar': ctypes.c_wchar,

            'str': ctypes.c_char_p,
            'wstr': ctypes.c_wchar_p,

            'bool': ctypes.c_bool,

            'byte': ctypes.c_byte,
            'ubyte': ctypes.c_ubyte
        }

    def ctypes_array(self, data_type, values):
        array_type = data_type * len(values)
        return array_type(*values)

    def ctypes_structure(self, structure_type, **kwargs):
        instance = structure_type()
        for field, value in kwargs.items():
            setattr(instance, field, value)
        return instance

    def ctypes_pointer(self, data_type, value):
        return ctypes.pointer(data_type(value))

    def ctypes_array_pointer(self, data_type, values):
        array_type = data_type * len(values)
        array_instance = array_type(*values)
        return ctypes.pointer(array_instance)

    def ctypes_array_from_buffer(self, data_type, buffer):
        array_type = data_type * (len(buffer) // ctypes.sizeof(data_type))
        return array_type.from_buffer_copy(buffer)

    def ctypes_structure_from_buffer(self, structure_type, buffer):
        instance = structure_type.from_buffer_copy(buffer)
        return instance

    def ctypes_array_cast(self, source_array, target_data_type):
        return ctypes.cast(source_array, ctypes.POINTER(target_data_type))

    def ctypes_structure_cast(self, source_instance, target_structure_type):
        return ctypes.cast(ctypes.byref(source_instance), ctypes.POINTER(target_structure_type)).contents

    def ctypes_address(self, obj):
        return ctypes.addressof(obj)

    def ctypes_bytes(self, obj, size):
        return ctypes.string_at(ctypes.addressof(obj), size)

    def ctypes_buffer(self, obj, size):
        buffer = ctypes.create_string_buffer(size)
        ctypes.memmove(buffer, ctypes.addressof(obj), size)
        return buffer

    def ctypes_string(self, obj):
        return ctypes.string_at(ctypes.addressof(obj))

    def ctypes_wstring(self, obj):
        return ctypes.wstring_at(ctypes.addressof(obj))

    def ctypes_array_to_list(self, array):
        return list(array)

    def ctypes_structure_to_dict(self, structure_instance):
        return dict((field, getattr(structure_instance, field)) for field, _ in structure_instance._fields_)

class DLLAPI(CEncoding, CTypes):
    def __init__(self, library: str, local: bool = False, base_logger: logging.Logger | None = None) -> None:
        CEncoding.__init__(self)
        CTypes.__init__(self)

        self._libname = library if local else ctypes.util.find_library(library)
        
        if self._libname is None:
            raise ValueError(f"Library '{library}' not found. Specify the full path if it's a custom library.")
        
        try:
            self._lib: ctypes.CDLL = ctypes.CDLL(name=self._libname)
        except OSError as e:
            raise OSError(f"Failed to load library '{self._libname}': {e}")
        
        try:
            self._libc = ctypes.CDLL(
                name=ctypes.util.find_library('msvcrt' if os.name == 'nt' else 'c')
            )
        except OSError as e:
            raise OSError(f"Failed to load library '{self._libname}': {e}")

        self._logger = base_logger

    def call(self, attr: str | None, *args, **kwargs):
        func = getattr(self._lib, attr, None)

        if func is not None and callable(func):

            self._logger.debug(
                f"Called: {self.get_attr_info(attr=attr)}"
            ) if self._logger else None

            return func(*args, **kwargs)
        else:
            raise AttributeError(
                f"{attr} is not a callable attribute of {self._libc._name}"
            )
        
    def async_call(self, attr: str | None, *args, **kwargs):
        asyncio = importlib.import_module(
            name='asyncio'
        )

        async def async_wrapper():
            return self.call(attr, *args, **kwargs)

        return asyncio.run(async_wrapper())

    def get_attr(self, attr: str):
        attribute = getattr(self._libc, attr, None)
        if attribute is not None:
            return attribute
        else:
            raise AttributeError(
                f"{attr} is not an attribute of {self._lib._name}"
            )

    def check_attr_availability(self, attr: str):
        func = getattr(self._lib, attr, None)
        return callable(func)

    def get_attr_list(self):
        return dir(self._lib)

    def get_attr_name(self, attr: str):
        func = getattr(self._lib, attr, None)
        if func is not None and callable(func):
            return func.__name__
        else:
            raise AttributeError(
                f"{attr} is not a callable attribute of {self._lib._name}"
            )

    def get_attr_address(self, attr: str):
        func = getattr(self._lib, attr, None)
        if func is not None and callable(func):
            return ctypes.addressof(func)
        else:
            raise AttributeError(
                f"{attr} is not a callable attribute of {self._lib._name}"
            )
        
    def get_attr_info(self, attr: str):
        func = getattr(self._lib, attr, None)
        if func is not None and callable(func):
            info = {
                'name': self.get_attr_name(attr),
                'address': self.get_attr_address(attr)
            }
            return info
        else:
            raise AttributeError(f"{attr} is not a callable attribute of {self._lib._name}")

    def alloc_string_buffer(self, text: str):
        encoded_text = text.encode(self._encoding)
        buffer = ctypes.create_string_buffer(encoded_text)
        return buffer
    
    def free_allocated_mem(self, buffer):
        self._libc.free(buffer)
