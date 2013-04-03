#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# ============================================================================
# Copyright (c) Martin P. Hellwig <martin.hellwig@gmail.com> 14 Mar 2013     
# All rights reserved.
# ============================================================================
#
""" """
# 6.4 SHA-512 Hash Computation
from _functions import pad
from _binary import Bits
from _constants_and_initials import H0_SHA_512, K_SHA_512

# 1. Introduction - Figure 1: Secure Hash Algorithm Properties
SIZE_WORD = 64
SIZE_BLOCK = 1024

def rotate_right(word, amount):
    binary = word._binary
    rotate = binary[-amount:] + binary[:-amount] 
    return_value = Bits(rotate, SIZE_WORD)
    return(return_value)

def shift_right(word, amount):
    binary = word._binary
    shift = binary[:-amount]
    return_value = Bits(shift, SIZE_WORD)
    return(return_value)

def function_ch(b, c, d):
    # (4.1.3)
    value = (b & c) | ((~ b) & d)
    return(value)

def function_maj(b, c, d):
    # (4.1.3)
    value = (b & c) | (b &d ) | (c & d)
    return(value)

def sigma_upper_512_0(x):
    # (4.1.3)
    value = rotate_right(x, 28) ^ rotate_right(x, 34) ^ rotate_right(x, 39)
    return(value)

def sigma_upper_512_1(x):
    # (4.1.3)
    value = rotate_right(x, 14) ^ rotate_right(x, 18) ^ rotate_right(x, 41)
    return(value)

def sigma_lower_512_0(x):
    # (4.1.3)
    value = rotate_right(x, 1) ^ rotate_right(x, 8) ^ shift_right(x, 7)
    return(value)

def sigma_lower_512_1(x):
    # (4.1.3)
    value = rotate_right(x, 19) ^ rotate_right(x, 61) ^ shift_right(x, 6)
    return(value)


def computation(message):
    # 6.4.1 SHA-512 Preprocessing
    # 5.1.2 Padding the Message
    padded = pad(message, SIZE_BLOCK)
    #  5.2.2 Parsing the Padded Message 
    #  ! Meaning splitting it into blocks of 1024 bits
    blocks = padded.split(SIZE_BLOCK)
    # 5.3 Setting the Initial Hash Value (H(0)) / 5.3.5 SHA-512
    hd = H0_SHA_512
    h0 = Bits(hd[0], SIZE_WORD)
    h1 = Bits(hd[1], SIZE_WORD)
    h2 = Bits(hd[2], SIZE_WORD)
    h3 = Bits(hd[3], SIZE_WORD)
    h4 = Bits(hd[4], SIZE_WORD)
    h5 = Bits(hd[5], SIZE_WORD)
    h6 = Bits(hd[6], SIZE_WORD)
    h7 = Bits(hd[7], SIZE_WORD)
    # 6. SECURE HASH ALGORITHMS
    # 6.4.2 SHA-512 Hash Computation
    for block in blocks:
        # Step 1. Prepare the message schedule
        # - Fill with 80 64 bits word values
        message_schedule = dict()
        # This set's up the first 16 words, using the words in the block
        for count, word in enumerate(block.split(SIZE_WORD)):
            word = Bits(word, SIZE_WORD)
            message_schedule[count] = word
            
        # This set's up the remaining 64 words
        for index in range(16, 80):
            # Implementation Note: 
            # The following code-block is an on-liner in the documentation,
            # see the 16<=t<=79 part of the equation
            w02 = message_schedule[index-2]
            w07 = message_schedule[index-7]
            w15 = message_schedule[index-15]
            w16 = message_schedule[index-16]
            #
            sl1 = sigma_lower_512_1(w02)
            sl0 = sigma_lower_512_0(w15)
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
            
        # Step 3. 80 rounds of calculation
        for index in range(80):
            
            kt = Bits(K_SHA_512[index], SIZE_WORD)
            wt = message_schedule[index]
            ch = function_ch(e, f, g)
            s1 = sigma_upper_512_1(e)
            t1 = h + s1 + ch + kt + wt
            
            s0 = sigma_upper_512_0(a)
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
        h0 = (h0 + a)
        h1 = (h1 + b)
        h2 = (h2 + c)
        h3 = (h3 + d)
        h4 = (h4 + e)
        h5 = (h5 + f)
        h6 = (h6 + g)
        h7 = (h7 + h)
    
    return(h0, h1, h2, h3, h4, h5, h6, h7)