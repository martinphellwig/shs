#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# ============================================================================
# Copyright (c) Martin P. Hellwig <martin.hellwig@gmail.com> 14 Mar 2013     
# All rights reserved.
# ============================================================================
#
# This implements a Bits/Integer like type, the content is stored as a string.
# Note that negative values are not stored as compliments but the flag 
# _negative is set. When doing bitwise operation if the flag is true I flip
# the bits first to emulate the python/c behaviour on x86/x64, however note
# that these kinds of bitwise behaviours are original platform depending.
# The PUB 180-3 assumes intel like behaviour and this how this type behaves.
""" """
class Bits(object):
    def __init__(self, content='', bit_size=0):
        self._negative = False 
        self._bit_size = bit_size
        self._binary = ''
        self._bitwise = {'and':{'00':'0',
                                '01':'0',
                                '10':'0',
                                '11':'1'},
                         'xor':{'00':'0',
                                '01':'1',
                                '10':'1',
                                '11':'0'},
                          'or':{'00':'0',
                                '01':'1',
                                '10':'1',
                                '11':'1'}}

        if isinstance(content, (str, unicode)):
            self._set_string(content)
        elif isinstance(content, (int, long)):
            self._set_number(content)
        elif isinstance(content, Bits):
            self._binary = content._binary
            self._negative = content._negative
            if bit_size == 0:
                self._bit_size = content._bit_size
        else:
            text = str(type(content))
            if text == 'class pyjslib.str':
                self._set_string(content)
            else:
                error = "Type '%s' can not be processed" % text
                raise(ValueError(error))
            
        self._set_size()
        
            
    def _set_size(self):
        if self._bit_size > 0:
            if len(self._binary) < self._bit_size:
                self._binary = self._binary.zfill(self._bit_size)
            elif len(self._binary) > self._bit_size:
                self._binary = self._binary[-self._bit_size:]
            
    def _all_bits(self, string):
        replace = ['0', '1']
        for character in replace:
            string = string.replace(character, '')
        if len(string) == 0:
            return(True)
        else:
            return(False) 
        
    def _set_string(self, string):
        is_byte_string = False
        valids = ['0b', '+0b', '-0b']
        for test in valids:
            if string.lower().startswith(test):
                is_byte_string = True
                
        if is_byte_string:
            test_bytes = string.lower().split('b')[1]
            if not self._all_bits(test_bytes):
                is_byte_string = False
        else:
            if self._all_bits(string):
                string = '0b' + string
                is_byte_string = True
                
        if is_byte_string:
            self._set_bits(string)
        else:
            self._set_text(string)
            
    def _bin(self, integer):
        # This converts an integer to a binary, unlike the python built-in
        # I always prefix with - or +.
        value = int(integer)
        prefix = '+'
        if value < 0:
            value = value * -1
            prefix = '-'
            
        tmp = list()
        while value > 0:
            append = value % 2
            tmp.insert(0, str(append))
            value = value / 2
        
        binary = prefix +'0b' + ''.join(tmp)
        return(binary)

    def _set_text(self, string):
        tmp = list()
        tmp.append(self._binary)
        for byte in string:
            numeric = ord(byte)
            binary = self._bin(numeric)[3:].zfill(8)
            tmp.append(binary)
        self._binary = ''.join(tmp)
            
    def _set_bits(self, bits):
        self._binary = bits.split('b')[1]
        if bits.startswith('-'):
            self._negative = True
            
    def _set_number(self, integer):
        if integer < 0:
            self._negative = True

        self._binary = self._bin(integer)[3:]
        
        
    def _equalise_length(self, them):
        len_them = len(them)
        len_self = len(self)
        
        one = Bits(self)
        two = Bits(them)
        
        if len_them > len_self:
            one._binary = one._binary.zfill(len_them)
        else:
            two._binary = two._binary.zfill(len_self)
            
        return(one, two)
            
    
    def _flip_bits(self):
        if self._negative:
            self._binary = self._binary.replace('1', 'T')
            self._binary = self._binary.replace('0', '1')
            self._binary = self._binary.replace('T', '0')
            self._negative = False
        
    def __invert__(self):
        bits = Bits(self)
        if bits._negative:
            bits._negative = False
        else:
            bits._negative = True
            
        return(bits)
    
    def _bitwise_operation(self, operation, them):
        mine, them = self._equalise_length(them)
        mine._flip_bits()
        them._flip_bits()
        tmp = list()
        for bit_pair in zip(mine._binary, them._binary):
            bits = ''.join(bit_pair)
            tmp.append(self._bitwise[operation][bits])
            
        binary = ''.join(tmp)
        bits = Bits()
        bits._binary = binary
        bits._bit_size = self._bit_size
        return(bits)
    
    def __and__(self, other):
        return(self._bitwise_operation('and', other))
    
    def __or__(self, other):
        return(self._bitwise_operation('or', other))
        
    def __xor__(self, other):
        return(self._bitwise_operation('xor', other))

    def __add__(self, other):
        one, two = self._equalise_length(other)
        number_one = int(one)
        number_two = int(two)
        value = number_one + number_two
        bits = Bits(value, one._bit_size)
        return(bits)
    
    def __repr__(self):
        if self._negative:
            prefix = '-'
        else:
            prefix = '+'
        return(prefix+'0b'+self._binary)
    
    def __int__(self):
        # Some interpreters, don't like three arguments indices and some 
        # others don't have the reverse method in list or the int type does 
        # not cope with binary, so doing it the hard way.
        integer = 0
        reversed_list = list()
        for character in self._binary:
            reversed_list.insert(0, character)

        for index, bit in enumerate(reversed_list):
            if bit == '1':
                plus = 2**index
                integer += plus

        if self._negative:
            integer = -1 * integer 
        return(integer)
        
    def __hex__(self):
        return(hex(self.__int__()))

    def __len__(self):
        return(len(self._binary))    

    def __cmp__(self, other):
        return(int(self).__cmp__(int(other)))
    
    def split(self, size):
        # This splits the binary in length specified, note a remainder may 
        # have a shorter size than specified.
        text = self._binary
        tmp = list()
        while len(text) > 0:
            part = text[:size]
            text = text[size:]
            bits = Bits(part)
            tmp.append(bits)
        return(tmp)
    
    def append(self, bits):
        # Appends the bits on the right.
        # Note that if you have a size specified and the resulting binary
        # is larger than that, it will be clipped on the left side
        if not isinstance(bits, Bits):
            bits = Bits(bits)
        
        self._binary += bits._binary
        self._set_size()

if __name__ == '__main__':
    x = Bits(1234567890)
    print(int(x))
        
