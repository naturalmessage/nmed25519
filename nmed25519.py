# The original version of this program came from http://ed25519.cr.yp.to
# and was issued by the original authors into the public domain
# Robert Hoot places any modifications in this file in the public domain 
# under the same terms as the original.

# The original contributers to the overal project include:
#    Daniel J. Bernstein, University of Illinois at Chicago
#    Niels Duif, Technische Universiteit Eindhoven
#    Tanja Lange, Technische Universiteit Eindhoven
#    Peter Schwabe, National Taiwan University
#    Bo-Yin Yang, Academia Sinica
# Authors of the Python program were not documented in the program.
#

# This is a Python 3 version of the original with added notes.
# There were no notes in the original.
# The notes here are partly to compare to the default process used by GNUPG
# for the purpose of creating a pure Python implementation that can
# read the ED25519 codes from GNUPG. 

import hashlib
import binascii
import sys

# Note from Hoot:
#   PROBLEM: the NIST paper from April 05, 2010, page 6, says that the 
#   compressed representation of a point is x with the least significant
#   bit of y, but this program (in encodepoint()) does it with x and y reversed
#   because this program uses the Edwards affine representation.
#   The Libgcrypt default in _gcry_mpi_ec_get_affine() in mpi/ec.c is typically
#   called with the y argument as NULL. Libgcrypt defaults to Weierstrass
#   affine transformation as opposed to Twisted Edwards.
#
sys.setrecursionlimit(10000) # Bob test 


# Notes from Hoot:
#   Notes in the sign.py file indicate that 'sk' is the secret key, which has the
#   public key attached to the end of it--each is 64 bytes of hex characters.
#   
#   During signing, 'm' could be considered the 'message' and sm is the signature
#   of the message combined with the message itself at the end of it (output of
#   the signing process?).
#   
#   The parameters sent to the signing function are convered from string/hex into binary
#   using binascii.unhexlify

#   Globals used in the functions below:
b = 256
q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493

# Notes from Hoot (trying to decipher the code on the first read)
#   'm' is the message (in python bytes format?),
#   and H(m) returns the binary hash of m.
def H(m):
  return(hashlib.sha512(m).digest())

def expmod(b,e,m):
  if e == 0: return(1)
  #t = expmod(b,e/2,m)**2 % m
  t = expmod(b, int(e//2), m)**2 % m  # bob added int() for Python 3
  # If e is odd, let t = "the old t times the bit depth" mod m
  if int(e) & 1: t = int(t*b) % m # bob added int() for Python 3
  return(t)

def inv(x):
  return(expmod(x,q-2,q))

# More globals that apply below:
d = -121665 * inv(121666)
I = expmod(2,(q-1)//4,q)

# Given a y value, and globals for d, I and q,
# that define the curve, find the corresponding x value? 
def xrecover(y):
  xx = (y*y-1) * inv(d*y*y+1)
  x = expmod(xx,(q+3)//8,q)
  if (x*x - xx) % q != 0: x = (x*I) % q
  if x % 2 != 0: x = q-x
  return(x)

# More globals... base points?
By = 4 * inv(5)
Bx = xrecover(By)
B = [Bx % q,By % q]

# the P and Q values appear to be list objects containing x,y ordered elements.
# This calculates the point on the curve where the line crosses the curve?
def edwards(P,Q):
  x1 = P[0]
  y1 = P[1]
  x2 = Q[0]
  y2 = Q[1]
  x3 = (x1*y2+x2*y1) * inv(1+d*x1*x2*y1*y2)
  y3 = (y1*y2+x1*x2) * inv(1-d*x1*x2*y1*y2)
  return([x3 % q,y3 % q])

def scalarmult(P,e):
  if e == 0: return([0,1])
  Q = scalarmult(P, e//2) # converted to //
  Q = edwards(Q,Q)
  if e & 1: Q = edwards(Q,P)
  return(Q)

def encodeint(y):
  bits = [(y >> i) & 1 for i in range(b)]
  #return(''.join([chr(sum([bits[i * 8 + j] << j for j in range(8)])) for i in range(b//8)]))
  return(bytes([sum([bits[i * 8 + j] << j for j in range(8)]) for i in range(b//8)]))

def encodepoint(P):
  x = P[0]
  y = P[1]
  # this creates a list of integers (1 or 0) of length 256
  ### Original version took most of y and one bit from x
  # The following is consistent with Twisted Edwards
  # (Weierstrass uses x and y reversed).
  bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]

  ##return(''.join([chr(sum([bits[i * 8 + j] << j for j in range(8)])) for i in range(b//8)]))
  ## original version converted to Python 3:
  return(bytes([sum([bits[i * 8 + j] << j for j in range(8)]) for i in range(b//8)]))

def bit(h,i):
  # h is now a Python bytes() object.
  ##return (ord(h[i//8]) >> (i%8)) & 1 # bob converted to floor division to get integer result
  return((h[i//8] >> (i%8)) & 1) # bob converted to floor division to get integer result

def publickey(sk):
  # Bob notes:
  #   The public key can be derived from the "secrete key" (sk)
  #   by hashing it and using the transformation below.
  h = H(sk)
  a = 2**(b-2) + sum(2**i * bit(h,i) for i in range(3,b-2))
  A = scalarmult(B,a)
  return(encodepoint(A))

# Hint gets the integer value of the hash of something,
# using global bitcount and bit length 'b'.
def Hint(m):
  h = H(m)
  return(sum(2**i * bit(h,i) for i in range(2*b)))

def bytes_to_int(bb):
  i_tmp = []  
  i_tmp.extend(bb)
  # should this be os.byteorder?
  return(int.from_bytes(i_tmp, 'little'))

def signature(m,sk,pk):
  # Compare to libgcrypt cipher/ecc-ecdsa.c" _gcry_ecc_ecdsa_sign() ?
  h = H(sk)
  a = 2**(b-2) + sum(2**i * bit(h,i) for i in range(3,b-2))
  ###r = Hint(''.join([h[i] for i in range(b/8,b/4)]) + m)
  ## converted to bytes object and floor division
  r = Hint(b''.join([h[b//8: b//4] , m]))
  R = scalarmult(B,r)
  ##   print ('==== in sig, l is type ' + str(type(l)))
  ##   print ('==== in sig, m is type ' + str(type(m)))
  ##   print ('==== in sig, h is type ' + str(type(h)))
  ##   print ('==== in sig, a is type ' + str(type(a)))
  ##   print ('==== in sig, r is type ' + str(type(r)))
  ##   print ('==== in sig, R is type ' + str(type(R)))
  ## ==== in sig, l is type <class 'int'>
  ## ==== in sig, m is type <class 'bytes'>
  ## ==== in sig, h is type <class 'bytes'>
  ## ==== in sig, a is type <class 'int'>
  ## ==== in sig, r is type <class 'int'>
  ## ==== in sig, R is type <class 'list'>

  #### originay Python 2 version:
  ####S = (r + Hint(encodepoint(R) + pk + m) * a) % l
  ####

  ### Reorganized for Python 3:
  # Try gluing the contents of the parens as bytes()
  # then converting it to an int)
  pR = encodepoint(R)
  print('== pR is len ' + str(len(pR)) + ' type ' + str(type(pR)) + ' value is ' + str(pR))
  zz = Hint(b''.join([pR, pk, m]))
  # I need integers here
  m_int = bytes_to_int(m)

  S = (r + zz  * a) % l
  part1 = encodepoint(R)
  part2 = encodeint(S)
  print('  length of signature part 1 ' + str(len(part1)) + ' len 2 ' + str(len(part2)))
  print('  type of signature part 1   ' + str(type(part1)) + ' type 2 ' + str(type(part2)))
  return(b''.join([part1, part2]))

def isoncurve(P):
  x = P[0]
  y = P[1]
  return((-x*x + y*y - 1 - d*x*x*y*y) % q == 0)

def decodeint(s):
  return(sum(2**i * bit(s,i) for i in range(0,b)))

# Given an integer value s that represents a signature,
# parse out the x and y components of the point:
def decodepoint(s):
  y = sum(2**i * bit(s,i) for i in range(0,b-1))
  x = xrecover(y)
  if x & 1 != bit(s,b-1): x = q-x
  P = [x,y]
  if not isoncurve(P): raise Exception("decoding point that is not on curve")
  return(P)

# This is the verify routine.
# s = The signature as a single, 64-byte integer (where the signature was
#     derived from the private key and the SHA512 hash of the data),
#     (it appears that the first 32 bytes of s contains R and the second
#     part contains S)
# m = a Python bytes object representing the original data (my guess
#     based on the H() function and notes in sign.py ).
# pk = the public key (in bytes format that were convered from hex 
#      using binascii.unhexlify)
def checkvalid(s,m,pk):
  print(' in check valid, s len is ' + str(len(s)) + ' and should be ' + str(b//4))
  print(' in check valid, m len is ' + str(len(m)))
  print(' in check valid, pk len is ' + str(len(pk)) + ' and should be ' + str(b//8))
  if len(s) != b//4: raise Exception("signature length is wrong")
  if len(pk) != b//8: raise Exception("public-key length is wrong")
  R = decodepoint(s[0:b//8])
  A = decodepoint(pk)
  S = decodeint(s[b//8:b//4])
  h = Hint(encodepoint(R) + pk + m)
  smult = scalarmult(B,S)
  print('test scalarmult ' + str(smult))
  ed2 = edwards(R,scalarmult(A,h))
  print('test ed2        ' + str(ed2))
  if smult != ed2:
    print('looks bad')
    raise Exception("signature does not pass verification")
  else:
    print('looks good')

  return(0)

########################################################################
