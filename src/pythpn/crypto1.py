# -*- coding: utf-8 -*-
import os, sys, string, struct
import random, heapq, itertools

# 把值val按位长width进行按位序反转,注意不限于32位val值
def reverse_bits(val, width):
  b = '{:0{width}b}'.format(val, width=width)
  return long(b[::-1], 2)

# 取val值第n位的值,值域为[0,1]
def bit(val, n):
  return (val >> n) & 1

# 取state值的ntable中的所有位进行异或
def xor_table_bits(state, ntable):
  fb = 0
  for n in ntable:
    fb ^= bit(state, n)
  return fb & 1

FORWARD_FBTABLE = [ 0, 5, 9,10,12,14,15,17,19,24,25,27,29,35,39,41,42,43]
RESTORE_FBTABLE = [ 48,5, 9,10,12,14,15,17,19,24,25,27,29,35,39,41,42,43]

# 计算crypto1算法中LFSR的线性反馈位值
def forward_fbbit(state):
  return xor_table_bits(state, FORWARD_FBTABLE)

# 恢复LFSR需要用到的,计算回溯LFSR时的线性反馈位值
def restore_fbbit(state):
  return xor_table_bits(state, RESTORE_FBTABLE)

# cipher的第一层过滤器fa
def f4a(y0, y1, y2, y3):
  return ((y0 | y1) ^ (y0 & y3)) ^ (y2 & ((y0 ^ y1) | y3))

# cipher的第一层过滤器fb
def f4b(y0, y1, y2, y3):
  return ((y0 & y1) | y2) ^ ((y0 ^ y1) & (y2 | y3))

# cipher的第二层过滤器fc
def f5c(y0, y1, y2, y3, y4):
  return (y0 | ((y1 | y4) & (y3 ^ y4))) ^ ((y0 ^ (y1 & y3)) & ((y2 ^ y3) | (y1 & y4)))

# 取x的第a,b,c,d位值,按低到高次序组合成4位字节,用于从布尔值表中取值
def i4bit(x, a, b, c, d):
  ret  = ((x >> a) & 1) << 0
  ret |= ((x >> b) & 1) << 1
  ret |= ((x >> c) & 1) << 2
  ret |= ((x >> d) & 1) << 3
  return ret
  
# cipher的过滤器实现,通过布尔值表快速实现
def filterbit_(s):
  f2_f4b = 0x9E98
  f2_f4a = 0xB48E
  f2_f5c = 0xEC57E80A  
  i5  = ((f2_f4a >> i4bit(s,  9, 11, 13, 15)) & 1) << 0
  i5 |= ((f2_f4b >> i4bit(s, 17, 19, 21, 23)) & 1) << 1
  i5 |= ((f2_f4b >> i4bit(s, 25, 27, 29, 31)) & 1) << 2
  i5 |= ((f2_f4a >> i4bit(s, 33, 35, 37, 39)) & 1) << 3
  i5 |= ((f2_f4b >> i4bit(s, 41, 43, 45, 47)) & 1) << 4
  return (f2_f5c >> i5) & 1

# cipher的过滤器实现,标准实现.
def filterbit(s):
  b = f5c(f4a(bit(s,  9), bit(s, 11), bit(s, 13), bit(s, 15)),
          f4b(bit(s, 17), bit(s, 19), bit(s, 21), bit(s, 23)),
          f4b(bit(s, 25), bit(s, 27), bit(s, 29), bit(s, 31)),
          f4a(bit(s, 33), bit(s, 35), bit(s, 37), bit(s, 39)),
          f4b(bit(s, 41), bit(s, 43), bit(s, 45), bit(s, 47)))
  return b

# LFSR移动一位
def lfsr_rollforward_bit(state, inbit):
  return (state >> 1) | ((forward_fbbit(state) ^ inbit) << 47)

def lfsr_rollforward_multi_bit(state, inputval, rollcount, isfeedback):
  keystream = 0
  for i in xrange(rollcount):
    keybit = filterbit(state)
    keystream = (keystream << 1) | keybit
    feedbit = forward_fbbit(state)
    inputbit = bit(inputval, i)
    inbit = inputbit
    if isfeedback:
      inbit ^= keybit
    prevstate = state
    state = lfsr_rollforward_bit(state, inbit)
  return state, reverse_bits(keystream, rollcount)
  
# LFSR移动rollcount位,isfeedback为真时,表示过滤器的密钥流同时会作为反馈输入
def cipher_rollforward(cipher, inputval, rollcount, isfeedback):
  cipher.state, keystream = lfsr_rollforward_multi_bit(cipher.state, inputval, rollcount, isfeedback)
  return keystream

# 回溯LFSR一位
def lfsr_rollback_bit(state, inbit, isfeedback):
  state = state << 1
  if isfeedback:
    keybit = filterbit(state)
  else:
    keybit = 0
  #prevstate = state #& 0xFFFFFFFFFFFF
  state = (state | ((restore_fbbit(state) ^ inbit ^ keybit) & 1)) & 0xFFFFFFFFFFFF
  #print '%013X -> %012X %s %s %d %d' % (prevstate, state, "{0:049b}".format(prevstate), "{0:048b}".format(state), inbit, keybit)  
  return state

def lfsr_rollback_multi_bit(state, inputval, rollcount, isfeedback):
  for i in xrange(rollcount):
    inputbit = bit(inputval, rollcount-i-1)
    prevstate = state
    state = lfsr_rollback_bit(state, inputbit, isfeedback)
  return state

# 回溯LFSR rollcount位,isfeedback为真时,过滤器输出的密钥流将作为LFSR的反馈输入位
def cipher_rollback(cipher, inputval, rollcount, isfeedback):
  cipher.state = lfsr_rollback_multi_bit(cipher.state, inputval, rollcount, isfeedback)
  return cipher.state

# 得到下n个伪随机数
NONCE_TABLE = [16,18,19,21]
def get_nonce_successor(nonce, n=1):
  for i in xrange(n*32):
    fb = xor_table_bits(nonce, NONCE_TABLE)
    nonce = (nonce >> 1) | (fb << 31)
  return nonce

def sf20(s):
  f2_f4b = 0x9E98
  f2_f4a = 0xB48E
  f2_f5c = 0xEC57E80A
  i5  = ((f2_f4a >> i4bit(s,  0,  1,  2,  3)) & 1) << 0
  i5 |= ((f2_f4b >> i4bit(s,  4,  5,  6,  7)) & 1) << 1
  i5 |= ((f2_f4b >> i4bit(s,  8,  9, 10, 11)) & 1) << 2
  i5 |= ((f2_f4a >> i4bit(s, 12, 13, 14, 15)) & 1) << 3
  i5 |= ((f2_f4b >> i4bit(s, 16, 17, 18, 19)) & 1) << 4
  return (f2_f5c >> i5) & 1

def lf20(s):
  f2_f4b = 0x9E98
  f2_f4a = 0xB48E
  f2_f5c = 0xEC57E80A  
  i5  = ((f2_f4a >> i4bit(s,  9, 11, 13, 15)) & 1) << 0
  i5 |= ((f2_f4b >> i4bit(s, 17, 19, 21, 23)) & 1) << 1
  i5 |= ((f2_f4b >> i4bit(s, 25, 27, 29, 31)) & 1) << 2
  i5 |= ((f2_f4a >> i4bit(s, 33, 35, 37, 39)) & 1) << 3
  i5 |= ((f2_f4b >> i4bit(s, 41, 43, 45, 47)) & 1) << 4
  return (f2_f5c >> i5) & 1

def filterbit_(s):
  f2_f4b = 0x9E98
  f2_f4a = 0xB48E
  f2_f5c = 0xEC57E80A  
  i5  = ((f2_f4a >> i4bit(s,  9, 11, 13, 15)) & 1) << 0
  i5 |= ((f2_f4b >> i4bit(s, 17, 19, 21, 23)) & 1) << 1
  i5 |= ((f2_f4b >> i4bit(s, 25, 27, 29, 31)) & 1) << 2
  i5 |= ((f2_f4a >> i4bit(s, 33, 35, 37, 39)) & 1) << 3
  i5 |= ((f2_f4b >> i4bit(s, 41, 43, 45, 47)) & 1) << 4
  return (f2_f5c >> i5) & 1

def lfsr_unassemble(value):
  s = 0
  t = 0
  for i in xrange(24):
    s |= bit(value, i*2+0) << i
    t |= bit(value, i*2+1) << i
  return s, t

def lfsr_assemble(s, t):
  value = 0
  for i in xrange(24):
    value |= bit(s, i) << (i*2)
    value |= bit(t, i) << (i*2+1)
  return value

class SemiStatus:
  def __init__(self, value, fbc21, fbc24):
    self.value = value
    self.fbc21 = fbc21
    self.fbc24 = fbc24

class EvenSemiTable(list):
  def __init__(self, *args):
    list.__init__(self, *args)
    
  def __cmp__(self, other):
    return cmp((self.fbc24, self.fbc21), (other.fbc24, other.fbc21))
  
class OddSemiTable(list):
  def __init__(self, *args):
    list.__init__(self, *args)
    
  def __cmp__(self, other):
    return cmp((self.fbc21, self.fbc24), (other.fbc21, other.fbc24))
  
def insert_table(table, i, value, fbc21, fbc24):
  semi = SemiStatus(value, fbc21, fbc24)
  table.insert(i, semi)

def append_table(table, value, fbc21, fbc24):
  semi = SemiStatus(value, fbc21, fbc24)
  table.append(semi)
  
FBC21_TABLE = [2,4,7,8,9,12,13,14,17,19,20,21]    
def fbc21_bit(value):
  bit = xor_table_bits(value, FBC21_TABLE)
  return bit

FBC24_TABLE = [0,5,6,7,12,21,24]
def fbc24_bit(value):
  bit = xor_table_bits(value, FBC24_TABLE)
  return bit

def update_fbc21_fbc24(table, i, shiftcnt):
  semi = table[i]
  value = (semi.value >> shiftcnt)
  semi.fbc21 = (semi.fbc21 << 1) | fbc21_bit(value)
  semi.fbc24 = (semi.fbc24 << 1) | fbc24_bit(value)
  
def init_table(table, b0):
  for i in itertools.count(2**20):
    if sf20(i) == b0:
      if i == 0x0fffdf:
        pass
      append_table(table, i, 0, 0)

def extend_table(table, b, extcnt):
  i = 0
  while i < len(table):
    cur = table[i]
    value = cur.value
    newval1 = (value >> extcnt) | (1 << 19)
    newval2 = (value >> extcnt) | (0 << 19)
    flag = 0
    if sf20(newval1) == b:
      flag |= 1
    if sf20(newval2) == b:
      flag |= 2
    if flag == 0:
      del table[i]
    elif flag == 1:
      cur.value = newval1
      if extcnt > 4:
        update_fbc21_fbc24(table, i, extcnt-4)
      i += 1
    elif flag == 2:
      cur.value = newval2
      if extcnt > 4:
        update_fbc21_fbc24(table, i, extcnt-4)
      i += 1
    elif flag == 3:
      cur.value = newval1
      insert_table(table, i, newval2, cur.fbc21, cur.fbc24)
      if extcnt > 4:
        update_fbc21_fbc24(table, i+0, extcnt-4)
        update_fbc21_fbc24(table, i+1, extcnt-4)
      i += 2

def get_table_result_fbc(evntbl, oddtbl, rewindbitcount):
  evnheap = heapq.heapify(evntbl)
  oddheap = heapq.heapify(oddtbl)
  result = []
  try:
    evn = evnheap.heappop()
    odd = oddheap.heappop()
    while true:
      if   evn.fbc21 > odd.fbc24:
        odd = oddheap.heappop()
      elif evn.fbc21 < odd.fbc24:
        evn = evnheap.heappop()
      elif evn.fbc24 > odd.fbc21:
        odd = oddheap.heappop()
      elif evn.fbc21 < odd.fbc24:
        evn = evnheap.heappop()
      else:
        value = lfsr_assemble(evn.value, odd.value)
        state = lfsr_rollback_multi_bit(value, 0, 9 + rewindbitcount, 0)
        result.append(state)
  except IndexError:
    pass
  return result
  
def recover_lfsr_status(keystream, length, rewindbitcount):
  print '=== Decrypto1 ==='
  print 'Init Tables....'
  evntbl = EvenSemiTable([])
  oddtbl = OddSemiTable([])
  init_table(evntbl, bit(keystream, 0))
  init_table(oddtbl, bit(keystream, 1))
  print 'Done (even table: %d, odd table: %d)' % (len(evntbl), len(oddtbl))
  print 'Extending Tables...'
  extcnt = 0
  for i in xrange(2, length, 2):
    extend_table(evntbl, bit(keystream, i+0), extcnt)
    extend_table(oddtbl, bit(keystream, i+1), extcnt)
    extcnt += 1
  print 'Done (even table: %d, odd table: %d)' % (len(evntbl), len(oddtbl))

  print 'Getting Results...'
  result = get_table_result_fbc(evntbl, oddtbl, rewindbitcount)
  print 'Done (%d results)' % len(result)
  return result

def my_recover_lfsr_status():
  keystream = 0xDE32C3A5F4C842FC #  ks2: fc42c8f4, ks3: a5c332de
  length = 64
  rewindbitcount = 0
  result = recover_lfsr_status(keystream, length, rewindbitcount)
  for status in result:
    print '%012X' % status
  print 'game over!'

def my_lf20():
  for i in xrange(100):
    value = random.randint(0, 0xFFFFFFFFFFFF)
    even, odd = lfsr_unassemble(value)
    if sf20(odd >> 4) != filterbit(value):
      print '%x' % value

def my_xrange():
  for i in itertools.count(2**20):
    if i >= 2**20-1:
      print '%08x' % i
      break

def my_init_table():
  table = EvenSemiTable([])
  init_table(table, 0)
  
if __name__ == '__main__':
  #my_lf20()
  #my_recover_lfsr_status()
  #my_xrange()
  my_init_table()
  
  


  
  
  