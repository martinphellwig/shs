#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# ============================================================================
# Copyright (c) Martin P. Hellwig <martin.hellwig@gmail.com> 14 Mar 2013     
# All rights reserved.
# ============================================================================
#
# This module is coded against FIPS PUB 180-3
# Which can be found at: 
# csrc.nist.gov/publications/fips/fips180-3/fips180-3_final.pdf
#
# Implementation note, the sha functions are split into these modules:
# _sha1, _sha224, _sha256, _sha384 and _sha512.
# The modules have a lot of code in common which on purpose have not been
# factored out to keep the FIPS specification more in line with the code.
#
# A Bits class has been implemented in the module _binary, which emulates
# an integer binary type using text as a back-end, this is done so we remove 
# the dependency on how c bitwise operation works, specifically for 
# signed/unsigned numbers when doing complement operations.
#
# All of this means that it is probably the slowest hash implementation in the 
# known universe, however it is hopefully also the most readable one.
#
# Where appropriate I have commented the relevant section of the standard in 
# the code.
""" """
from _sha_1 import computation as _sha_1
from _sha_256 import computation as _sha_256
from _sha_224 import computation as _sha_224
from _sha_512 import computation as _sha_512
from _sha_384 import computation as _sha_384

class SHA(object):
    """Secure Hash Algorithm, digest_size must be a one of 160, 224, 256, 384 
    or 512."""
    def __init__(self, digest_size=512):
        # Fetch the appropriate algorithm.
        digests = {160:_sha_1,
                   224:_sha_224,
                   256:_sha_256,
                   512:_sha_512,
                   384:_sha_384}
        
        self._computation = digests[digest_size]    
        self.content = '' # This must be a bytestring
        
    def update(self, message):
        self.content += message # updates a bytestring
        # The built-in python implementation is optimised to intermediate
        # hash the blocks; for readability purpose I have not done this.
    
    def digest(self):
        tmp = list()
        return_value = self._computation(self.content)
        for binary in return_value:
            binary = binary._binary
            while len(binary) > 0:
                byte = int(binary[:8], 2)
                binary = binary[8:]
                character = chr(byte)
                tmp.append(character)
            
        return(''.join(tmp))
            
    def hexdigest(self):
        tmp = list()
        for byte in self.digest():
            hexed = hex(ord(byte))[2:].zfill(2)
            tmp.append(hexed)
        return(''.join(tmp))
    
    
def main():
    import hashlib
    message = 'This is a message'

    print('# Testing this code (TC) against Python built-in (BI)')
    print('# Hashing Message:"%s"' % message)
    print('#' * 79)
    
    
    print('# - Sha 1')
    sha = hashlib.sha1()
    sha.update(message)
    print('BI:'),
    print(sha.hexdigest())
    print('TC:'),
    sha = SHA(160)
    sha.update(message)
    print(sha.hexdigest())
    print('#' * 79)
    
    print('# - Sha 224')
    sha = hashlib.sha224()
    sha.update(message)
    print('BI:'),
    print(sha.hexdigest())
    print('TC:'),
    sha = SHA(224)
    sha.update(message)
    print(sha.hexdigest())
    print('#' * 79)

    print('# - Sha 256')
    sha = hashlib.sha256()
    sha.update(message)
    print('BI:'),
    print(sha.hexdigest())
    print('TC:'),
    sha = SHA(256)
    sha.update(message)
    print(sha.hexdigest())
    print('#' * 79)

    print('# - Sha 384')
    sha = hashlib.sha384()
    sha.update(message)
    print('BI:'),
    print(sha.hexdigest())
    print('TC:'),
    sha = SHA(384)
    sha.update(message)
    print(sha.hexdigest())
    print('#' * 79)    
    
    print('# - Sha 512')
    sha = hashlib.sha512()
    sha.update(message)
    print('BI:'),
    print(sha.hexdigest())
    print('TC:'),
    sha = SHA(512)
    sha.update(message)
    print(sha.hexdigest())
    print('#' * 79)    
    
    
if __name__ == '__main__':
    main()
    