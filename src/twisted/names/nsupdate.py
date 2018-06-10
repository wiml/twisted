"""
Utilities for secure dynamic DNS updates, protected by transaction
signatures using TSIG or SIG(0) RRs.
"""

import base64, hmac, hashlib, io, re, struct, time

from twisted.names import dns
import zope.interface

import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.backends
import cryptography.hazmat.primitives as primitives



class ITransactionKey(zope.interface.Interface):
    """
    A key which can be used to authenticate DNS transactions such as UPDATE.
    """

    def signMessage(message, header, body):
        """
        Construct a transaction signature record (e.g. TSIG or SIG(0))
        for a message.

        The existing transaction signature methods compute a digest
        over a version of the message without the signature RR
        added; this serialized version is passed in as the
        concatenation of header and body.

        @type message: C{Message}
        @param message: The message object being signed.
        @type header: C{bytes}
        @param header: The serialized header of the message being
            signed.
        @type body: C{bytes}
        @param body: The serialized body of the message being signed.

        @rtype: L{twisted.names.dns.RRHeader}
        @return The signature record or C{None}.
        """



@zope.interface.implementer(ITransactionKey)
class HMACTransactionKey (object):
    """
    A key for authenticating DNS transactions using HMAC and a shared
    secret.
    """

    def __init__(self, name, algorithm, secret, truncation=None, fudge=5):
        """
        Initialize a new HMAC transaction key.

        @type name: C{str} representing a DNS name
        @param name: The name of this key.
        @type algorithm: C{str} representing a DNS name
        @param algorithm: The HMAC algorithm used to generate signatures.
        @type secret: C{bytes}
        @param secret: The secret shared authentication key.
        @type truncation: C{int}
        @param truncation: The length in bytes to which to truncate the HMAC.
            Defaults to C{None}, indicating the full length of the HMAC.
        @type fudge: C{int}
        @param fudge: The allowable offset between the signer's and
            verifier's clocks, in seconds.
        """
        self.name = name
        algorithm = algorithm.lower()
        if algorithm == 'hmac-sha224':
            self.digestmod = hashlib.sha224
        elif algorithm == 'hmac-sha256':
            self.digestmod = hashlib.sha256
        elif algorithm == 'hmac-sha384':
            self.digestmod = hashlib.sha384
        elif algorithm == 'hmac-sha512':
            self.digestmod = hashlib.sha512
        elif algorithm == 'hmac-md5.sig-alg.reg.int':
            self.digestmod = hashlib.md5
            algorithm = algorithm.upper()
        else:
            raise ValueError('Unknown algorithm identifier: %r' % (algorithm,))
        self.algorithm = algorithm
        self.truncation = truncation
        self.secret = secret
        self.fudge = fudge


    def _newContext(self):
        return hmac.HMAC(self.secret, digestmod=self.digestmod)


    def now(self):
        return int(time.time())


    def signMessage(self, message, header, body):
        ctxt = self._newContext()
        ctxt.update(header)
        ctxt.update(body)

        signingTime = self.now()

        # Encode a subset of our RDATA. See RFC 2845 section 3.4.2.
        extra = io.BytesIO()
        dns.Name(self.name).encode(extra, None)
        extra.write(struct.pack('!HL', dns.ANY, 0))
        dns.Name(self.algorithm).encode(extra, None)
        extra.write(struct.pack('!QHHH',
                                signingTime, self.fudge,
                                0,  # error is 0 in requests
                                0   # otherData is empty in requests
        )[2:])
        ctxt.update(extra.getvalue())

        mac = ctxt.digest()
        if self.truncation is not None:
            mac = mac[:self.truncation]

        rdata = dns.Record_TSIG(self.algorithm,
                                signingTime, self.fudge,
                                originalID=message.id,
                                MAC=mac)
        rr = dns.RRHeader(self.name, type=dns.TSIG, cls=dns.ANY, ttl=0,
                          payload=rdata)
        return rr



class SIGTransactionKey (object):
    """
    Common superclass for SIG(0) transaction keys.
    """

    def __init__(self, dnsAlgorithm, hashAlgorithm,
                 name, keyTag, offset=1, fudge=5,
                 backend=None):
        self.algorithm = dnsAlgorithm
        self.hashAlgorithm = hashAlgorithm
        self.offset = offset
        self.fudge = fudge
        self.keyTag = keyTag
        self.name = name
        if backend is None:
            self.backend = cryptography.hazmat.backends.default_backend()
        else:
            self.backend = backend


    def now(self):
        return int(time.time())


    def signMessage(self, message, header, body):

        signingTime = self.now()

        sig0 = dns.Record_SIG(
            typeCovered=0,
            algorithm=self.algorithm,
            labels=0,
            originalTTL=0,
            inception=signingTime + self.offset - self.fudge,
            expiration=signingTime + self.offset + self.fudge,
            keyTag=self.keyTag,
            signer=self.name,
            signature=None)

        extra = io.BytesIO()
        sig0.encode(extra, compDict=None, excludeSignature=True)

        hashContext = primitives.hashes.Hash(self.hashAlgorithm,
                                             backend=self.backend)

        hashContext.update(extra.getvalue())
        del extra
        hashContext.update(header)
        hashContext.update(body)

        sig0.signature = self._signDigest(hashContext)

        sig0_rr = dns.RRHeader('', type=dns.SIG, cls=dns.ANY, ttl=0,
                               payload=sig0)

        return sig0_rr


    def _signDigest(self, hashContext):
        raise NotImplementedError()



@zope.interface.implementer(ITransactionKey)
class RSA_SIGTransactionKey (SIGTransactionKey):
    """
    Signs transactions using RSA (RFC3110, etc).
    """

    def __init__(self, key, algorithm, **kwargs):
        """
        @type key: L{cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey}
        @type algorithm: L{twisted.names.dns.DNSSEC_ALG}
        @type name: C{str}
        @type offset: C{int}
        @type fudge: C{int}
        @type keyTag: C{int}

        """

        if algorithm == dns.DNSSEC_ALG.RSA_MD5:
            hashAlgorithm = primitives.hashes.MD5()
        elif algorithm == dns.DNSSEC_ALG.RSA_SHA1:
            hashAlgorithm = primitives.hashes.SHA1()
        elif algorithm == dns.DNSSEC_ALG.RSA_SHA256:
            hashAlgorithm = primitives.hashes.SHA256()
        elif algorithm == dns.DNSSEC_ALG.RSA_SHA512:
            hashAlgorithm = primitives.hashes.SHA512()
        else:
            raise ValueError('Unknown RSA sig type %d' % (algorithm,))
        super().__init__(algorithm, hashAlgorithm, **kwargs)
        self.private_key = key


    def _signDigest(self, hashContext):
        hashValue = hashContext.finalize()
        padding = primitives.asymmetric.padding.PKCS1v15()
        wrap = primitives.asymmetric.utils.Prehashed(hashContext.algorithm)
        return self.private_key.sign(hashValue, padding, wrap)



@zope.interface.implementer(ITransactionKey)
class ECDSA_SIGTransactionKey (SIGTransactionKey):
    """
    Signs transactions using ECDSA on a NIST curve (RFC6605)
    """

    def __init__(self, key, algorithm, **kwargs):
        """
        @type key: L{cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey}
        @type algorithm: L{twisted.names.dns.DNSSEC_ALG}
        @type name: C{str}
        @type offset: C{int}
        @type fudge: C{int}
        @type keyTag: C{int}
        """
        if algorithm == dns.DNSSEC_ALG.ECDSAP384SHA384:
            hashAlgorithm = primitives.hashes.SHA384()
        elif algorithm == dns.DNSSEC_ALG.ECDSAP256SHA256:
            hashAlgorithm = primitives.hashes.SHA256()
        else:
            raise ValueError('Unknown ECDSA sig type %d' % (algorithm,))
        super().__init__(algorithm, hashAlgorithm, **kwargs)
        self.private_key = key


    def _signDigest(self, hashContext):
        hashValue = hashContext.finalize()
        wrap = primitives.asymmetric.utils.Prehashed(hashContext.algorithm)
        der = self.private_key.sign(
            hashValue,
            primitives.asymmetric.ec.ECDSA(wrap))
        (r, s) = primitives.asymmetric.utils.decode_dss_signature(der)
        keyLen = (self.private_key.key_size + 7) // 8
        return ( r.to_bytes(keyLen, byteorder='big', signed=False) +
                 s.to_bytes(keyLen, byteorder='big', signed=False) )



def readBINDPrivateKey(fp, backend, **kwargs):
    """
    Read a private key in BIND format from a file.

    Currently, this only supports the version 1.3 private key format
    for asymmetric keys (RSA and EC).

    @param fp: A file-like object, or other object providing
        an iteration of lines
    @param backend: The cryptography backend
    @param kwargs: Arguments to pass to the L{ITransactionKey} initializer
        in addition to the key object and its algorithm. Typically this
        includes C{name}.
    @rtype An L{ITransactionKey} instance
    """

    lines = []
    pat = re.compile('^([A-Z][A-Za-z0-9_-]+):\s+(.*)$')
    format_val = None
    keytype_val = None
    for line in fp:
        if not line:
            break
        line = line.rstrip()
        if not line:
            continue
        m = pat.match(line)
        if not m:
            raise ValueError('Invalid line in BIND private key file')
        if m.group(1) == 'Private-key-format':
            format_val = m.group(2)
        elif m.group(1) == 'Algorithm':
            keytype_val = m.group(2)
        else:
            lines.append( (m.group(1), m.group(2)) )
    if format_val != 'v1.3' or not keytype_val:
        raise ValueError('Not a BIND private key v1.3 file')
    keyalg = int(keytype_val.partition(' ')[0])
    if keyalg in (dns.DNSSEC_ALG.RSA_MD5, dns.DNSSEC_ALG.RSA_SHA1,
                  dns.DNSSEC_ALG.RSA_SHA256, dns.DNSSEC_ALG.RSA_SHA512):
        privkey = _extractRSANumbers(lines).private_key(backend)
        return RSA_SIGTransactionKey(key=privkey,
                                     algorithm=keyalg,
                                     backend=backend, **kwargs)
    elif keyalg in (dns.DNSSEC_ALG.ECDSAP256SHA256, dns.DNSSEC_ALG.ECDSAP384SHA384):
        if keyalg == dns.DNSSEC_ALG.ECDSAP256SHA256:
            curve = primitives.asymmetric.ec.SECP256R1()
        elif keyalg == dns.DNSSEC_ALG.ECDSAP384SHA384:
            curve = primitives.asymmetric.ec.SECP384R1()
        [ secret ] = list( t[1] for t in lines if t[0] == 'PrivateKey' )
        secretNumber = int.from_bytes(base64.b64decode(secret), byteorder='big')
        privkey = primitives.asymmetric.ec.derive_private_key(
            secretNumber, curve, backend)
        return ECDSA_SIGTransactionKey(key=privkey,
                                       algorithm=keyalg,
                                       backend=backend, **kwargs)
    else:
        raise ValueError('Unknown/unsupported key type %r' % (keytype_val,))



_BINDRSANumbers = { 'Modulus': 'n',
                    'PublicExponent': 'e',
                    'PrivateExponent': 'd',
                    'Prime1': 'p',
                    'Prime2': 'q',
                    'Exponent1': 'dmp1',
                    'Exponent2': 'dmq1',
                    'Coefficient': 'iqmp' }
def _extractRSANumbers(lines):
    """
    Internal function to convert the RSA parameters in a BIND private key
    file to a RSAPrivateNumbers object.
    """
    nums = dict()
    for (k, v) in lines:
        field = _BINDRSANumbers.get(k)
        if field is not None:
            nums[field] = int.from_bytes(base64.b64decode(v), byteorder='big')
    pubpart = primitives.asymmetric.rsa.RSAPublicNumbers(nums['e'], nums['n'])
    privpart = primitives.asymmetric.rsa.RSAPrivateNumbers(
        nums['p'], nums['q'], nums['d'],
        nums['dmp1'], nums['dmq1'], nums['iqmp'],
        public_numbers=pubpart)
    return privpart



def makePubKeyRDATAFragment(numbers, algorithm):
    """
    Given public key parameters, compute the key data field of a
    L{twisted.names.dns.KEY} or L{twisted.names.dns.DNSKEY}
    representing that key.

    @type numbers:
     L{cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicNumbers} or
     L{cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers}
    @param numbers: The public key's components
    @type algorithm: L{twisted.names.dns.DNSSEC_ALG}
    @param algorithm: The RR's algorithm
    @rtype: C{bytes}

    """
    if algorithm in (dns.DNSSEC_ALG.RSA_MD5, dns.DNSSEC_ALG.RSA_SHA1,
                     dns.DNSSEC_ALG.RSA_SHA256, dns.DNSSEC_ALG.RSA_SHA512):
        if not isinstance(numbers, primitives.asymmetric.rsa.RSAPublicNumbers):
            raise TypeError('Key type does not match algorithm')
        # RFC 2537 section 2; RFC 3110 section 2
        expsize = (numbers.e.bit_length() + 7) // 8
        if expsize < 256:
            rdata = struct.pack('!B', expsize)
        else:
            rdata = struct.pack('!BH', 0, expsize)
        rdata += numbers.e.to_bytes(expsize, byteorder='big', signed=False)
        modsize = (numbers.n.bit_length() + 7) // 8
        rdata += numbers.n.to_bytes(modsize, byteorder='big', signed=False)
        return rdata
    elif algorithm in (dns.DNSSEC_ALG.ECDSAP256SHA256, dns.DNSSEC_ALG.ECDSAP384SHA384):
        if not isinstance(numbers, primitives.asymmetric.ec.EllipticCurvePublicNumbers):
            raise TypeError('Key type does not match algorithm')
        # RFC 6605 section 4
        point = numbers.encode_point()
        assert point.startswith(b'\x04') # Uncompressed point format is required by DNS
        return point[1:]
    else:
        raise ValueError('Unknown key algorithm')
