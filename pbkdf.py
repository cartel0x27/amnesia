#!/usr/bin/python

"""
Given a password p, salt s and length l, output a NIST SP800-132 compliant Master Key.

Implements PBKDF2.
original : http://matt.ucc.asn.au/src/pbkdf2.py

# (c) 2004 Matt Johnston <matt @ ucc asn au>
# This code may be freely used, distributed, relicensed, and modified for any
# purpose.
"""

from Crypto.Hash import SHA256
import hmac
import binascii
from struct import pack, unpack
import warnings


def prf( h, data ):
	hm = h.copy()
	hm.update( data )
	return hm.digest()

def xorstr( a, b ):
	if len(a) != len(b):
		raise "xorstr(): lengths differ"

	ret = ''
	for i in range(len(a)):
		ret += chr(ord(a[i]) ^ ord(b[i]))
	return ret


def pbkdf2_F( h, salt, itercount, blocknum ):
	U = prf( h, salt + pack('>i',blocknum ) )
	T = U

	for i in range(2, itercount+1):
		U = prf( h, U )
		T = xorstr( T, U )

	return T

def pbkdf(password, salt, itercount=10**5, keylen=32, hashfn = SHA256):
        """ callme """
        warnings.simplefilter("ignore", RuntimeWarning,0)
        digest_size = hashfn.digest_size
	# l - number of output blocks to produce
	l = keylen / digest_size
	if keylen % digest_size != 0:
		l += 1
	h = hmac.new( password, None, hashfn )
	T = ""
	for i in range(1, l+1):
		T += pbkdf2_F( h, salt, itercount, i )
	return T[0: keylen]

def hexdigest(ret):
    return "".join(map(lambda c: '%02x' % ord(c), ret))

if __name__ == "__main__":
    password  = "Those who work for the few die by the many."
    salt = binascii.unhexlify("1234567878563412")
    rounds = 10 ** 6
    keylen = 32 # bytes
    print "Iterating..."
    ret = pbkdf( password, salt, rounds, keylen )
    hexret = "".join(map(lambda c: '%02x' % ord(c), ret))
    print "key: %s "%hexret
