#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# ============================================================================
# Copyright (c) Martin P. Hellwig <martin.hellwig@gmail.com> 14 Mar 2013     
# All rights reserved.
# ============================================================================
#
""" """
# 6.1 SHA-1 Hash Computation
from _functions import pad
from _binary import Bits
from _constants_and_initials import H0_SHA_1, K_SHA_1

# 1. Introduction - Figure 1: Secure Hash Algorithm Properties 
SIZE_WORD = 32
SIZE_BLOCK = 512

def rotate_left(word, amount):
    # 2.2.2 # ROTLn(x)
    binary = word._binary
    rotate = binary[amount:] + binary[:amount] 
    return_value = Bits(rotate, SIZE_WORD)
    return(return_value)

def function_ch(b, c, d):
    # 4.1.1 - (4.1) # 0 <= t <= 19
    value = (b & c) | ((~ b) & d)
    return(value)

def function_maj(b, c, d):
    # 4.1.1 - (4.1) # 40 <= t <= 59
    value = (b & c) | (b &d ) | (c & d)
    return(value)

def function_parity(b, c, d):
    # 4.1.1 - (4.1) #  20 <= t <= 39; 60 <= t <= 79
    value = b ^ c ^ d
    return(value)

SHA1_FUNCTIONS = dict() # 4.1.1 - (4.1) # Map the logical functions
for index in range(0, 20):
    SHA1_FUNCTIONS[index] = function_ch
for index in range(20, 40):
    SHA1_FUNCTIONS[index] = function_parity
for index in range(40, 60):
    SHA1_FUNCTIONS[index] = function_maj
for index in range(60, 80):
    SHA1_FUNCTIONS[index] = function_parity
     

def computation(message):
    # 6.1.1 SHA-1 Preprocessing
    # 5.1 Padding the Message
    padded = pad(message, SIZE_BLOCK)
    
    #  5.2 Parsing the Padded Message / 5.2.1 SHA-1
    #  ! Meaning splitting it into blocks of 512 bits
    blocks = padded.split(SIZE_BLOCK)
    
    # 5.3 Setting the Initial Hash Value (H(0)) / 5.3.1 SHA-1
    h0 = Bits(H0_SHA_1[0], SIZE_WORD)
    h1 = Bits(H0_SHA_1[1], SIZE_WORD)
    h2 = Bits(H0_SHA_1[2], SIZE_WORD)
    h3 = Bits(H0_SHA_1[3], SIZE_WORD)
    h4 = Bits(H0_SHA_1[4], SIZE_WORD)
    
    # 6. SECURE HASH ALGORITHMS
    # 6.1.2 SHA-256 Hash Computation
    for block in blocks:
        # Step 1. Prepare the message schedule
        # - Fill with 80 32 bits word values # 6.1 First Paragraph
        message_schedule = dict()

        # 0 <= t <= 15
        # This set's up the first 16 words, using the words in the block
        # As the block can only have 16 words, we do not have to worry about
        # remainders.
        for count, word in enumerate(block.split(SIZE_WORD)):
            word = Bits(word, SIZE_WORD)
            message_schedule[count] = word
            
        # 16 <= t <= 79
        # This set's up the remaining 64 words
        for index in range(16, 80):
            # Implementation Note: 
            # The following code-block is an on-liner in the documentation.
            w03 = message_schedule[index-3]
            w08 = message_schedule[index-8]
            w14 = message_schedule[index-14]
            w16 = message_schedule[index-16]
            #
            word = w03 ^ w08 ^ w14 ^ w16
            word = rotate_left(word, 1)
            #
            message_schedule[index] = word
        
        # Step 2. Initialize 5 working variables
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
            
        # Step 3. 80 rounds of calculation
        for index in range(80):               
            ft =  SHA1_FUNCTIONS[index]
            kt = Bits(K_SHA_1[index], SIZE_WORD)
            wt = message_schedule[index]
            
            t = rotate_left(a, 5) + ft(b, c, d) + e  + kt + wt
            e = d 
            d = c 
            c = rotate_left(b, 30)
            b = a 
            a = t
        
        # Step 4. compute the intermediate hash value    
        h0 = a + h0 
        h1 = b + h1 
        h2 = c + h2 
        h3 = d + h3
        h4 = e + h4
    
    return(h0, h1, h2, h3, h4)