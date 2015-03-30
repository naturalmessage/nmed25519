# tst01.py
# this is a test of nmed25519 using one original and one modified test value
# from http://ed25519.cr.yp.to/python/sign.input
# mainly for studying the algorithm.
#
# A test using codes from libgcrypt ed25519 (default settngs) did not work 
# because libgcrypt uses Weierstrass affine transformations.
#
import binascii
import sys
import nmed25519

########################################################################
# system test of known good from the test script made by the original author
print('=========================================== TEST 1')
line = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a:d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a::e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b:'

x = line.split(':')
sk = binascii.unhexlify(x[0][0:64])
pk = nmed25519.publickey(sk)
m = binascii.unhexlify(x[2])
s = nmed25519.signature(m,sk,pk)

print('==== before checkvalid, sig is ' + str(s))
rc = nmed25519.checkvalid(s,m,pk)

expected_sig = binascii.unhexlify(x[3])
if s != expected_sig:
  print('observed sig did not match expected sig')
else:
  print('signature looks good')

print('')
#########################################################################
########################################################################
# system test of known bad (last byte of pub key changed in two places )
print('=========================================== TEST 2')
line = '66666666666666666666666666666666666666666666666666666666666666666666666662b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511b:d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511b::e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b:'

x = line.split(':')
sk = binascii.unhexlify(x[0][0:64]) # bytes() object
pk = nmed25519.publickey(sk)
m = binascii.unhexlify(x[2]) # bytes() object
s = nmed25519.signature(m,sk,pk) # bytes() object
print('==== before checkvalid, sig is ' + str(s))
	
# This check is merely checking that the signature is good based on the
# new inputs: a fake secret key with all 6s and the new public
# key that was derived from the secret key (the public key
# part of the input 'line' is not read.
# This should verify, but the signature should not match
# the signature from the unaltered 'line' that came from
# the original author's test script.
rc = nmed25519.checkvalid(s,m,pk)

expected_sig = binascii.unhexlify(x[3])
if s != expected_sig:
  print('observed sig did not match expected sig -- I altered the keys, so I expected this to fail')
else:
  print('signature looks good')

print('')

#########################################################################
