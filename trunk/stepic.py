#!/usr/bin/python
'''twistinc: twitter steganographic image netcat

todo:
twitpic api integration
twitter streaming api
option parser
iv

steg functionality derived from stepic.
Stepic uses the Python Image Library
twitpix functionality derived from python-twitpic, http://code.google.com/p/python-twitpic
rc4 keystream function from export-a-crypto-system

'''

__author__ = 'pnegry & others'
__version__ = '0.1'


import warnings
from xml.dom import minidom as xml
import httplib, mimetypes
from urllib import urlopen
from StringIO import StringIO
try:
    import Image
except:
    warnings.warn('Could not find PIL. Only encode_imdata and decode_imdata will work.',
                  ImportWarning, stacklevel=2)


def rc4_keystream(secret):
   t,x,y,j,s,a=range(256),0,0,0,1,secret
   k=(map(lambda b:[ord(x) for x in a][b], range(len(a)))*256)[:256] 
   for i in t:
       j=(k[i]+t[i]+j)%256
       t[i],t[j]=t[j],t[i] 
   while True:
       x=(x+1)%256;y=(y+t[x])%256
       t[x],t[y]=t[y],t[x]
       yield t[(t[x]+t[y])%256]
       
class pixel_stream():
    def __init__(self, image, keystream):
       self.used = []
       self.image = image
       self.x, self.y = image.size
       self.keystream = keystream

    def next(self):
        while True:
            x = (self.keystream.next() * self.keystream.next()) % self.x
            y = (self.keystream.next() * self.keystream.next()) % self.y
            try: 
                self.used.index((x,y)) 
            except ValueError:
                break
        self.used.append((x,y))
        return self.image.getpixel((x,y)), x, y


def encode_imdata(imdata, data, secret):
    try:
        datalen = len(data)
    except TypeError:
        raise ValueError('data is empty')
    if datalen * 3 > len(imdata.getdata()):
        raise ValueError('data is too large for image')

    imdata = pixel_stream(imdata, rc4_keystream(secret))

    for i in xrange(datalen):
        p = imdata.next() + imdata.next() + imdata.next()
        pixels = [value & ~1 for value in p[0] + p[3] + p[6]]
        
        byte = ord(data[i]) ^ imdata.keystream.next()
        for j in xrange(7, -1, -1):
            pixels[j] |= byte & 1
            byte >>= 1
        if i == datalen - 1:
            pixels[-1] |= 1
        pixels = tuple(pixels)
        yield pixels[0:3], p[1], p[2]
        yield pixels[3:6], p[4], p[5]
        yield pixels[6:9], p[7], p[8]


def encode_inplace(image, data, secret):
    '''hides data in an image'''
    for pixel, x, y in encode_imdata(image, data, secret):
        image.putpixel((x, y), pixel)


def encode(image, data, secret=None):
    '''generates an image with hidden data, starting with an existing
    image and arbitrary data'''
    image = image.copy()
    data == "" if data == None else data
    encode_inplace(image, data, secret)
    return image
    
def encode_png(image, message, secret):
    i = encode(image, message, secret)
    buf=StringIO()
    i.save(buf, format= 'PNG')
    return buf.getvalue()


def decode_imdata(imdata, secret):
    '''Given a sequence of pixels, returns an iterator of characters
    encoded in the image'''
    
    imdata = pixel_stream(imdata, rc4_keystream(secret))
    while True:
        p = imdata.next() + imdata.next() + imdata.next()
        pixels = [value for value in p[0] + p[3] + p[6]]
        byte = 0
        for c in xrange(7):
            byte |= pixels[c] & 1
            byte <<= 1
        byte |= pixels[7] & 1
        yield chr(byte ^ imdata.keystream.next())
        if pixels[-1] & 1:
            break


def decode(image, secret):
    '''extracts data from an image'''
    return ''.join(decode_imdata(image.getdata(), secret))

