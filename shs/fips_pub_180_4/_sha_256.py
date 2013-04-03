#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# ============================================================================
# Copyright (c) Martin P. Hellwig <martin.hellwig@gmail.com> 14 Mar 2013     
# All rights reserved.
# ============================================================================
#
""" """
# 6.2 SHA-256 Hash Computation
from _functions import pad
from _binary import Bits
from _constants_and_initials import H0_SHA_256, K_SHA_256

# 1. Introduction - Figure 1: Secure Hash Algorithm Properties
SIZE_WORD = 32
SIZE_BLOCK = 512

def rotate_right(word, amount):
    # 2.2.2 Symbols and Operations # ROTRn(x)
    binary = word._binary
    rotate = binary[-amount:] + binary[:-amount] 
    return_value = Bits(rotate, SIZE_WORD)
    return(return_value)

def shift_right(word, amount):
    # 2.2.2 Symbols and Operations # SHRn(x)
    binary = word._binary
    shift = binary[:-amount]
    return_value = Bits(shift, SIZE_WORD)
    return(return_value)

def function_ch(b, c, d):
    # 4.1.2 - (4.2)
    value = (b & c) | ((~ b) & d)
    return(value)

def function_maj(b, c, d):
    # 4.1.2 - (4.3)
    value = (b & c) | (b &d ) | (c & d)
    return(value)

def sigma_upper_256_0(x):
    # 4.1.2 - (4.4)
    value = rotate_right(x, 2) ^ rotate_right(x, 13) ^ rotate_right(x, 22)
    return(value)

def sigma_upper_256_1(x):
    # 4.1.2 - (4.5)
    value = rotate_right(x, 6) ^ rotate_right(x, 11) ^ rotate_right(x, 25)
    return(value)

def sigma_lower_256_0(x):
    # 4.1.2 - (4.6)
    value = rotate_right(x, 7) ^ rotate_right(x, 18) ^ shift_right(x, 3)
    return(value)

def sigma_lower_256_1(x):
    # 4.1.2 - (4.7)
    value = rotate_right(x, 17) ^ rotate_right(x, 19) ^ shift_right(x, 10)
    return(value)


def computation(message):
    # 5. Preprocessing
    # 5.1 Padding the Message
    padded = pad(message, SIZE_BLOCK)
    #  5.2 Parsing the Padded Message / 5.2.1 SHA-1, SHA-224 and SHA-256
    #  ! Meaning splitting it into blocks of 512 bits
    blocks = padded.split(SIZE_BLOCK)
    # 5.3 Setting the Initial Hash Value (H(0)) / 5.3.3 SHA-256
    hd = H0_SHA_256
    h0 = Bits(hd[0], SIZE_WORD)
    h1 = Bits(hd[1], SIZE_WORD)
    h2 = Bits(hd[2], SIZE_WORD)
    h3 = Bits(hd[3], SIZE_WORD)
    h4 = Bits(hd[4], SIZE_WORD)
    h5 = Bits(hd[5], SIZE_WORD)
    h6 = Bits(hd[6], SIZE_WORD)
    h7 = Bits(hd[7], SIZE_WORD)
    # 6. SECURE HASH ALGORITHMS
    # 6.2.2 SHA-256 Hash Computation
    for block in blocks:
        # Step 1. Prepare the message schedule
        # - Fill with 64 32 bits word values
        message_schedule = dict()
        # This set's up the first 16 words, using the words in the block
        # see the 0 <= t <= 15 part
        for count, word in enumerate(block.split(SIZE_WORD)):
            word = Bits(word, SIZE_WORD)
            message_schedule[count] = word
            
        # This set's up the remaining 48 words
        for index in range(16, 64):
            # Implementation Note: 
            # The following code-block is an on-liner in the documentation,
            # see the 16<=t<=63 part
            w02 = message_schedule[index-2]
            w07 = message_schedule[index-7]
            w15 = message_schedule[index-15]
            w16 = message_schedule[index-16]
            #
            sl1 = sigma_lower_256_1(w02)
            sl0 = sigma_lower_256_0(w15)
            word = sl1 + w07 + sl0 + w16  
            #
            message_schedule[index] = word
        
        # Step 2. Initialize working variables
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7
            
        # Step 3. 64 rounds of calculation
        for index in range(64):
            
            kt = Bits(K_SHA_256[index], SIZE_WORD)
            wt = message_schedule[index]
            ch = function_ch(e, f, g)
            s1 = sigma_upper_256_1(e)
            t1 = h + s1 + ch + kt + wt
            
            s0 = sigma_upper_256_0(a)
            ma = function_maj(a, b, c)
            t2 = s0 + ma
            
            h = g
            g = f
            f = e 
            e = d + t1
            d = c 
            c = b 
            b = a 
            a = t1 + t2
        
        # Step 4. compute the intermediate hash value    
        h0 = a + h0
        h1 = b + h1
        h2 = c + h2
        h3 = d + h3
        h4 = e + h4
        h5 = f + h5
        h6 = g + h6
        h7 = h + h7
    
    return(h0, h1, h2, h3, h4, h5, h6, h7)