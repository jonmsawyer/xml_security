#!/usr/bin/env python
#Coding: UTF-8

from StringIO import StringIO
import hmac
from hashlib import sha1
import base64
from lxml import etree as ET
import uuid

def c14n(xml, exclusive=True):
    io_msg = StringIO(xml)
    et = ET.parse(io_msg)
    io_output = StringIO()
    et.write_c14n(io_output, exclusive=exclusive)
    return io_output.getvalue()

def psha1(clientSecret, serverSecret, sizeBits=256, decodeSecrets=False):
    if decodeSecrets:
        clientSecret = base64.b64decode(clientSecret)
        serverSecret = base64.b64decode(serverSecret)
    sizeBytes = sizeBits / 8
    hashSize = 160 # HMAC_SHA1 length is always 160
    i = 0
    b1 = serverSecret
    b2 = ""
    temp = None
    psha = ""
    
    while i < sizeBytes:
        b1 = hmac.new(clientSecret, b1, sha1).digest()
        b2 = b1 + serverSecret
        temp = hmac.new(clientSecret, b2, sha1).digest()

        for j in xrange(0, len(temp)):
            if i < sizeBytes:
                psha += temp[j]
                i += 1
            else:
                break
    return base64.b64encode(psha)


## ONE ########################################################################
key_store = (
    '9DKqiWZPOvQuXIk5cuupIxzKVoz6BZ0X1gB1OwZ/G8E=',
    'icMFRGjveOK8LfW6QNw/5iLaknjWidTL3KEUT9sniDE=',
)

ts_store = (
    '''<u:Timestamp u:Id="_0" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><u:Created>2014-10-07T21:25:16.810Z</u:Created><u:Expires>2014-10-07T21:30:16.810Z</u:Expires></u:Timestamp>''',
    '''<SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1"></SignatureMethod><Reference URI="#_0"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod><DigestValue>zYIcnsphp4lPCK7REFYo4zT4tBU=</DigestValue></Reference></SignedInfo>''',
    '''<SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1"/><Reference URI="#_0"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>zYIcnsphp4lPCK7REFYo4zT4tBU=</DigestValue></Reference></SignedInfo>''',
)

known_signatures = (
    'zYIcnsphp4lPCK7REFYo4zT4tBU=', # request 2 digest value
    'U3B7nhKHc0prHvjHcRsWqP8bZcI=', # request 2 signature value
)


def decode_hmac(key, msg, decode_key=True):
    '''
    key - base64 encoded key
    msg - XML message
    '''
    
    if decode_key:
        try:
            key_raw = base64.b64decode(key)
        except:
            return ''
    else:
        key_raw = key
    
    canon = c14n(msg)
    sig = hmac.new(key_raw, canon, sha1)
    
    return base64.b64encode(sig.digest())

def decode_sha1(msg):
    '''
    msg - XML message
    '''
    
    canon = c14n(msg)
    sig = sha1(canon)
    
    return base64.b64encode(sig.digest())

def decode_multi(key_store, msg_store):
    for msg in msg_store:
        yield decode_sha1(msg)

def decode_multi_inline():
    for sig in decode_multi(key_store, ts_store):
        print sig
        if sig in known_signatures:
            print "        MATCH!!! %s" % (sig,)

def decode_psha1():
    key = key_store[0]
    seed = key_store[1]
    size = 256
    
    keys = []
    
    keys.append(psha1(key, seed, size, True))
    keys.append(psha1(key, seed, size, False))
    keys.append(psha1(seed, key, size, True))
    keys.append(psha1(seed, key, size, False))
    
    keys.append(psha1(key, '', size, True))
    keys.append(psha1(key, '', size, False))
    keys.append(psha1('', key, size, True))
    keys.append(psha1('', key, size, False))
    
    keys.append(psha1(seed, '', size, True))
    keys.append(psha1(seed, '', size, False))
    keys.append(psha1('', seed, size, True))
    keys.append(psha1('', seed, size, False))
    
    keys.append(psha1('', '', size, True))
    keys.append(psha1('', '', size, False))
    
    keys.append(psha1(seed, seed, size, True))
    keys.append(psha1(seed, seed, size, False))
    keys.append(psha1(key, key, size, True))
    keys.append(psha1(key, key, size, False))
    
    for h in keys:
        for store in ts_store:
            sig = decode_hmac(h, store)
            print sig
            if sig in known_signatures:
                print "     MATCH!!", sig
