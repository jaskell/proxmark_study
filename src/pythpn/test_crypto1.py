# -*- coding: utf-8 -*-
from nose.tools import ok_, eq_
from crypto1 import *

def test_bit():
  val = 0x12345678
  ok_(bit(val, 0) == 0, 'bit function 0 test failed!')
  ok_(bit(val, 1) == 0, 'bit function 1 test failed!')
  ok_(bit(val, 2) == 0, 'bit function 2 test failed!')
  ok_(bit(val, 3) == 1, 'bit function 3 test failed!')

def test_forward_fbbit():
  ok_(forward_fbbit(0xFFFFFFFFFFFF) == 0, 'forward_fbbit test failed!')
  ok_(forward_fbbit(0x7FFFFFFFFFFF) == 0, 'forward_fbbit test failed!')  
  ok_(forward_fbbit(0xBFFFFFFFFFFF) == 0, 'forward_fbbit test failed!')
  ok_(forward_fbbit(0xDFFFFFFFFFFF) == 0, 'forward_fbbit test failed!')  
  ok_(forward_fbbit(0xEFFFFFFFFFFF) == 0, 'forward_fbbit test failed!')
  ok_(forward_fbbit(0xF7FFFFFFFFFF) == 1, 'forward_fbbit test failed!')  
  ok_(forward_fbbit(0xFBFFFFFFFFFF) == 1, 'forward_fbbit test failed!')
  ok_(forward_fbbit(0xFDFFFFFFFFFF) == 1, 'forward_fbbit test failed!')  
  ok_(forward_fbbit(0xFEFFFFFFFFFF) == 0, 'forward_fbbit test failed!')
  ok_(forward_fbbit(0xFF7FFFFFFFFF) == 1, 'forward_fbbit test failed!')  
  ok_(forward_fbbit(0xFFBFFFFFFFFF) == 0, 'forward_fbbit test failed!')
  ok_(forward_fbbit(0xFFDFFFFFFFFF) == 0, 'forward_fbbit test failed!')  
  ok_(forward_fbbit(0xFFEFFFFFFFFF) == 0, 'forward_fbbit test failed!')
  ok_(forward_fbbit(0xFFF7FFFFFFFF) == 1, 'forward_fbbit test failed!')  
  ok_(forward_fbbit(0x7FFBFFFFFFFF) == 0, 'forward_fbbit test failed!')
  ok_(forward_fbbit(0xBFFDFFFFFFFF) == 0, 'forward_fbbit test failed!')  
  ok_(forward_fbbit(0xDFFEFFFFFFFF) == 0, 'forward_fbbit test failed!')
  ok_(forward_fbbit(0xEFFF7FFFFFFF) == 0, 'forward_fbbit test failed!')  
  ok_(forward_fbbit(0x77FFBFFFFFFF) == 1, 'forward_fbbit test failed!')
  ok_(forward_fbbit(0x3BFFDFFFFFFF) == 0, 'forward_fbbit test failed!')  
  ok_(forward_fbbit(0x9DFFEFFFFFFF) == 1, 'forward_fbbit test failed!')
  ok_(forward_fbbit(0xCEFFF7FFFFFF) == 1, 'forward_fbbit test failed!')  
  ok_(forward_fbbit(0xE77FFBFFFFFF) == 0, 'forward_fbbit test failed!')
  ok_(forward_fbbit(0x73BFFDFFFFFF) == 1, 'forward_fbbit test failed!')  
  ok_(forward_fbbit(0x39DFFEFFFFFF) == 1, 'forward_fbbit test failed!')
  ok_(forward_fbbit(0x9CEFFF7FFFFF) == 1, 'forward_fbbit test failed!')  
  ok_(forward_fbbit(0x4E77FFBFFFFF) == 0, 'forward_fbbit test failed!')
  ok_(forward_fbbit(0xA73BFFDFFFFF) == 0, 'forward_fbbit test failed!')  
  ok_(forward_fbbit(0xD39DFFEFFFFF) == 0, 'forward_fbbit test failed!')
  ok_(forward_fbbit(0xE9CEFFF7FFFF) == 1, 'forward_fbbit test failed!')  
  ok_(forward_fbbit(0xF4E77FFBFFFF) == 1, 'forward_fbbit test failed!')
  ok_(forward_fbbit(0x7A73BFFDFFFF) == 0, 'forward_fbbit test failed!')  
  
def test_lfsr_rollforward_bit():
  ok_(lfsr_rollforward_bit(0xFFFFFFFFFFFF, 0) == 0x7FFFFFFFFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0x7FFFFFFFFFFF, 1) == 0xBFFFFFFFFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0xBFFFFFFFFFFF, 1) == 0xDFFFFFFFFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0xDFFFFFFFFFFF, 1) == 0xEFFFFFFFFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0xEFFFFFFFFFFF, 1) == 0xF7FFFFFFFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0xF7FFFFFFFFFF, 0) == 0xFBFFFFFFFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0xFBFFFFFFFFFF, 0) == 0xFDFFFFFFFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0xFDFFFFFFFFFF, 0) == 0xFEFFFFFFFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0xFEFFFFFFFFFF, 1) == 0xFF7FFFFFFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0xFF7FFFFFFFFF, 0) == 0xFFBFFFFFFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0xFFBFFFFFFFFF, 1) == 0xFFDFFFFFFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0xFFDFFFFFFFFF, 1) == 0xFFEFFFFFFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0xFFEFFFFFFFFF, 1) == 0xFFF7FFFFFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0xFFF7FFFFFFFF, 1) == 0x7FFBFFFFFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0x7FFBFFFFFFFF, 1) == 0xBFFDFFFFFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0xBFFDFFFFFFFF, 1) == 0xDFFEFFFFFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0xDFFEFFFFFFFF, 1) == 0xEFFF7FFFFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0xEFFF7FFFFFFF, 0) == 0x77FFBFFFFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0x77FFBFFFFFFF, 1) == 0x3BFFDFFFFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0x3BFFDFFFFFFF, 1) == 0x9DFFEFFFFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0x9DFFEFFFFFFF, 0) == 0xCEFFF7FFFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0xCEFFF7FFFFFF, 0) == 0xE77FFBFFFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0xE77FFBFFFFFF, 0) == 0x73BFFDFFFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0x73BFFDFFFFFF, 1) == 0x39DFFEFFFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0x39DFFEFFFFFF, 0) == 0x9CEFFF7FFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0x9CEFFF7FFFFF, 1) == 0x4E77FFBFFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0x4E77FFBFFFFF, 1) == 0xA73BFFDFFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0xA73BFFDFFFFF, 1) == 0xD39DFFEFFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0xD39DFFEFFFFF, 1) == 0xE9CEFFF7FFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0xE9CEFFF7FFFF, 0) == 0xF4E77FFBFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0xF4E77FFBFFFF, 1) == 0x7A73BFFDFFFF, 'lfsr_rollforward_bit test failed!')
  ok_(lfsr_rollforward_bit(0x7A73BFFDFFFF, 0) == 0x3D39DFFEFFFF, 'lfsr_rollforward_bit test failed!')

def test_cipher_rollforward():
  class Cipher:
    pass
  cipher = Cipher()
  cipher.state = long(0xFFFFFFFFFFFF)
  keystream = cipher_rollforward(cipher, 0x5e8dfd1e, 32, 0)
  #print 'keystream: %08x, lfsr: %012x' % (keystream, cipher.state)
  ok_(cipher.state == 0x3d39dffeffff, 'cipher_rollforward test failed!')
  
def test_i4bit():
  ok_(i4bit(0xaaaa, 1, 3, 5, 7) == 0xF, 'test_i4bit test failed!')
  ok_(i4bit(0xaaaa, 2, 4, 6, 8) == 0x0, 'test_i4bit test failed!')
  
def test_get_nonce_successor():
  nonce = 0x6c16a482 #0x82a4166c
  nt2 = get_nonce_successor(nonce, 2)
  ok_(nt2 == 0x4b73658d, 'get_nonce_successor test failed!')
  nt3 = get_nonce_successor(nonce, 3)
  ok_(nt3 == 0x207b429a, 'get_nonce_successor test failed!')
  #print '%08x, %08x, %08x' % (nonce, nt2, nt3)  

def test_filterbit_match():
  for i in xrange(3200):
    s = random.randint(1, 0xFFFFFFFF)
    i5 = filterbit(s)
    oo = filterbit_(s)
    ok_(i5 == oo, 'filterbit and filterbit_ function mismatch!')
    
def test_cipher_rollforward1():
  class Cipher:
    pass
  cipher = Cipher()
  cipher.state = long(0xFFFFFFFFFFFF)
  val32 = 0x5e8dfd1e
  keystream = cipher_rollforward(cipher, val32, 32, 0)
  #print 'keystream: %08x, lfsr: %012x -> %012x' % (keystream, 0xFFFFFFFFFFFF, cipher.state)
  ok_(cipher.state == long(0x3d39dffeffff), 'cipher_rollforward test failed!')

  cipher.state = long(0x3d39dffeffff) #
  val32 = 0x712e6b4e #0xe2fac83d 4E6B2E71
  keystream = cipher_rollforward(cipher, val32, 32, 0)
  print 'keystream: %08x, lfsr: %012x -> %012x' % (keystream, 0x3d39dffeffff, cipher.state)
  ok_(cipher.state == long(0xeef57d4951e2), 'cipher_rollforward test failed!')
  
  cipher.state = long(0x51E2FAC83D39) #393dc8fae251
  val32 = 0x000000000
  keystream = cipher_rollforward(cipher, val32, 32, 0)
  #print 'keystream: %08x, lfsr: %012x -> %012x' % (keystream, 0x51E2FAC83D39, cipher.state)
  ok_(cipher.state == long(0xeef57d4951e2), 'cipher_rollforward test failed!')
  
  cipher.state = long(0xEEF57D4951E2) #e251497df5ee
  val32 = 0x000000000
  keystream = cipher_rollforward(cipher, val32, 32, 0)
  #print 'keystream: %08x, lfsr: %012x -> %012x' % (keystream, 0xEEF57D4951E2, cipher.state)
  ok_(cipher.state == long(0x8eca0d0beef5), 'cipher_rollforward test failed!')
  
def test_rollback2():
  class Cipher:
    pass
  cipher = Cipher()
  cipher.state = long(0x8eca0d0beef5) # lfsr: [f5ee0b0dca8e]
  val32 = 0
  cipher_rollback(cipher, val32, 32, 0)
  #print '%012x' % cipher.state # lfsr: [e251497df5ee] c6ef8f19
  ok_(cipher.state == 0xeef57d4951e2, 'cipher_rollback test failed!')
  cipher_rollback(cipher, val32, 32, 0)
  #print '%012x' % cipher.state # lfsr: [393dc8fae251]
  ok_(cipher.state == 0x51e2fac83d39, 'cipher_rollback test failed!')
  val32 = 0xce58e4a1 #{nr}: a1e458ce
  cipher_rollback(cipher, val32, 32, 1)
  #print '%012x' % cipher.state # lfsr: [e251497df5ee] c6ef8f19
  ok_(cipher.state == 0x3d39dffeffff, 'cipher_rollback test failed!')
  val32 = 0x329b599c ^ 0x6c16a482 # uid: 9c599b32  nt: 82a4166c
  cipher_rollback(cipher, val32, 32, 0)
  #print '%012x' % cipher.state # lfsr: [e251497df5ee] c6ef8f19
  ok_(cipher.state == 0xffffffffffff, 'cipher_rollback test failed!')

def test_rollback3():
  class Cipher:
    pass
  cipher = Cipher()
  cipher.state = 0x51e2fac83d39
  val32 = 0xce58e4a1 #{nr}: a1e458ce
  cipher_rollback(cipher, val32, 32, 1)
  #print '%012x' % cipher.state # lfsr: [e251497df5ee] c6ef8f19
  ok_(cipher.state == 0x3d39dffeffff, 'cipher_rollback test failed!')

def test_rollback4():
  class Cipher:
    pass
  cipher = Cipher()
  cipher.state = 0x51e2fac83d39
  val32 = 0xDA1CEAEF # 0xce58e4a1 ^ 0x14440e4e = 0xDA1CEAEF
  cipher_rollback(cipher, val32, 32, 0)
  #print '%012x' % cipher.state # lfsr: [e251497df5ee] c6ef8f19
  ok_(cipher.state == 0x3d39dffeffff, 'cipher_rollback test failed!')
  
def test_rollback5():
  class Cipher:
    pass
  cipher = Cipher()
  cipher.state = long(0xfc7deaaf3744) #lfsr: [4437afea7dfc]
  val32 = 0
  cipher_rollback(cipher, val32, 32, 0)
  #print '%012x' % cipher.state # lfsr: [d04e47054437] a5c332de
  ok_(cipher.state == 0x374405474ed0, 'cipher_rollback test failed!')
  cipher_rollback(cipher, val32, 32, 0)
  #print '%012x' % cipher.state # lfsr: [2c7e939fd04e] fc42c8f4
  ok_(cipher.state == 0x4ed09f937e2c, 'cipher_rollback test failed!')
  val32 = 0x9fc08306 #{nr}: 0683c09f
  cipher_rollback(cipher, val32, 32, 1)
  #print '%012x' % cipher.state # lfsr: [0009bad22c7e] fc42c8f4
  ok_(cipher.state == 0x7e2cd2ba0900, 'cipher_rollback test failed!')
  val32 = 0x8a886664 ^ 0x69adcd2b # uid: 6466888a  nt: 2bcdad69
  cipher_rollback(cipher, val32, 32, 0)
  #print '%012x' % cipher.state # [000000000009] fcc6c8f4  
  ok_(cipher.state == 0x090000000000, 'cipher_rollback test failed!')
  
def test_lfsr_assemble():
  ret = lfsr_assemble(0x1111, 0x0000)
  ok_(ret == 0x01010101, 'lfsr_assemble test failed!')
  ret = lfsr_assemble(0xFFFF, 0x0000)
  ok_(ret == 0x55555555, 'lfsr_assemble test failed!')
  
def test_lfsr_unassemble():
  even, odd = lfsr_unassemble(0x01010101)
  ok_(even == 0x1111, 'lfsr_unassemble test failed!')
  ok_(odd  == 0x0000, 'lfsr_unassemble test failed!')
  even, odd = lfsr_unassemble(0x55555555)
  ok_(even == 0xFFFF, 'lfsr_unassemble test failed!')
  ok_(odd  == 0x0000, 'lfsr_unassemble test failed!')
  