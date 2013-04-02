#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# ============================================================================
# Copyright (c) Martin P. Hellwig <martin.hellwig@gmail.com> 14 Mar 2013     
# All rights reserved.
# ============================================================================
#
""" """
from _binary import Bits

def pad(message, size):
    "Pad message to size, so that length message modulo size is 0"
    # 5.1 Padding the Message
    # Implementation note; because of the similarities of padding to 512 or 1024
    # and it is not 'core' to the algorithm, both "5.1.1 SHA-1, SHA-224 and 
    # SHA-256" and "5.1.2 SHA-384 and SHA-512" are implemented as one. 
    allowed_sizes = [512, 1024]
    if size not in allowed_sizes:
        text = "Split size '%s' not allowed must be in: %s"
        raise(ValueError(text % (size, allowed_sizes)))
    
    if size == 512:
        pad_len = 64
    elif size == 1024:
        pad_len = 128
    
    message = Bits(message)
    pad_txt = Bits(len(message), pad_len)
    message.append('1')
    
    
    length = len(message) + pad_len
    delta = length % size
    padding = size - delta
    padding = '0' * padding
    
    message.append(padding)
    message.append(pad_txt)
    return(message)     