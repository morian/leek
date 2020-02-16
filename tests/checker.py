#!/usr/bin/env python

from base64 import b64decode, b64encode, b32encode
from pyasn1_modules.rfc2437 import RSAPrivateKey, RSAPublicKey
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from hashlib import sha1

import os
import sys


class LeekKeyChecker(object):
    """ Handle private RSA keys generated for target services """


    def __init__(self, b64data):
        """ Get a new private key in base64 format (DER encoded) """
        self._prv_raw = None
        self._prv_key = None
        self._prv_b64 = b64data

        self._pub_raw = None
        self._pub_key = None
        self._pub_b64 = None

        self._domain = None


    @property
    def prv_b64(self):
        """ Returns the original base64 private key """
        return self._prv_b64

    @property
    def prv_der(self):
        """ Returns the original private key in raw DER format """
        if self._prv_raw is None:
            prvb64 = self.prv_b64
            self._prv_raw = b64decode(prvb64)
        return self._prv_raw


    @property
    def prv_key(self):
        """ Returns the parsed ASN1 private key """
        if self._prv_key is None:
            prvder = self.prv_der
            self._prv_key = der_decode(prvder, asn1Spec=RSAPrivateKey())[0]
        return self._prv_key


    @property
    def pub_key(self):
        """ Returns the ASN1 corresponding public key """
        if self._pub_key is None:
            prvkey = self.prv_key
            pubkey = RSAPublicKey()
            pubkey.setComponentByName('modulus', prvkey['modulus'])
            pubkey.setComponentByName('publicExponent', prvkey['publicExponent'])
            self._pub_key = pubkey
        return self._pub_key

    @property
    def pub_der(self):
        """ Returns the corresponding public key in DER format """
        if self._pub_raw is None:
            pubkey = self.pub_key
            self._pub_raw = der_encode(pubkey)
        return self._pub_raw

    @property
    def pub_b64(self):
        """ Returns the corresponding public key in base64 """
        if self._pub_b64 is None:
            pubder = self.pub_der
            self._pub_b64 = b64encode(pubder).decode('utf-8')
        return self._pub_b64

    @property
    def domain(self):
        """ Get the associated onion domain from public key """
        if self._domain is None:
            pubder = self.pub_der
            digest = sha1(pubder).digest()[0:10]
            self._domain = b32encode(digest).decode("utf-8").lower()
        return self._domain
# End of class LeekKeyChecker


def leek_check(filepath):
    """ Check leek output filename against content """
    filename = os.path.basename(filepath)
    claimed = filename.split('.')[0]
    success = False
    domain = ''

    with open(filepath, 'r') as fp:
        lines = fp.readlines()
        lkc = LeekKeyChecker(''.join(lines[1:-1]))
        domain = lkc.domain
        success = bool(domain == claimed)

    if success:
        print("Checking %s: OK (%s)" % (filename, domain))
    else:
        print("Checking %s: FAIL" % (filename,))

    return success


if __name__ == '__main__':
    for filepath in sys.argv[1:]:
        res = leek_check(filepath)
        if not res:
            sys.exit(1)
