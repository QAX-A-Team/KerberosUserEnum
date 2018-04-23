# kerberos accounts enumeration
# date: 2018-04-23
# author: n1nty @ 360 A-TEAM

from asn1crypto.core import Sequence, Integer, SequenceOf, BitString, GeneralString, GeneralizedTime, \
    OctetString, Any
import random
import datetime

APPLICATION = 1
CONTEXT = 2
PRIVATE = 3

KerberosFlags = BitString
KerberosString = GeneralString
KerberosTime = GeneralizedTime
Realm = KerberosString
Microseconds = Integer

class KDCOptions(KerberosFlags):
    _map = {
        0: 'reserved',
        1: 'forwardable',
        2: 'forwarded',
        3: 'proxiable',
        4: 'proxy',
        5: 'allow-postdate',
        6: 'postdated',
        7: 'unused7',
        8: 'renewable',
        9: 'unused9',
        10: 'unused10',
        11: 'opt-hardware-auth',
        12: 'unused12',
        13: 'unused13',
        15: 'unused15',
        26: 'disable-transited-check',
        27: 'renewable-ok',
        28: 'enc-tkt-in-skey',
        30: 'renew',
        31: 'validate',
    }


def make_sequence_of(basetype, explicit=None):
    t = type('x', (SequenceOf,), {'_child_spec': basetype})
    if explicit:
        t.explicit = explicit
    return t

class PaData(Sequence):
    _fields = [
        ('padata-type', Integer, {'explicit': 1}),
        ('padata-value', OctetString, {'explicit': 2})
    ]

class PrincpalName(Sequence):
    _fields = [
        ('name-type', Integer, {'explicit': 0}),
        ('name-string', make_sequence_of(KerberosString), {'explicit': 1})
    ]


class HostAddress(Sequence):
    _fields = [
        ('addr-type', Integer, {'explicit': 0}),
        ('address', OctetString, {'explicit': 1}),
    ]


HostAddresses = make_sequence_of(HostAddress)


class EncryptedData(Sequence):
    _fields = [
        ('etype', Integer, {'explicit': 0}),
        ('knvo', Integer, {'explicit': 1, 'optional': True}),
        ('cipher', OctetString, {'explicit': 2})
    ]


class Ticket(Sequence):
    explicit = (1, 1)
    _fields = [
        ('tkt-vno', Integer, {'explicit': 0}),
        ('realm', Realm, {'explicit': 1}),
        ('sname', PrincpalName, {'explicit': 2}),
        ('enc-part', EncryptedData, {'explicit': 3})
    ]

EType = make_sequence_of(Integer)
class KDCReqBody(Sequence):
    _fields = [
        ('kdc-options', KDCOptions, {'explicit': 0}),
        ('cname', PrincpalName, {'explicit': 1, 'optional': True}),
        ('realm', Realm, {'explicit': 2}),
        ('sname', PrincpalName, {'explicit': 3, 'optional': True}),
        ('from', KerberosTime, {'explicit': 4, 'optional': True}),
        ('till', KerberosTime, {'explicit': 5}),
        ('rtime', KerberosTime, {'explicit': 6, 'optional': True}),
        ('nonce', Integer, {'explicit': 7}),
        ('etype', EType, {'explicit': 8, 'optional': True}),
        ('address', HostAddresses, {'explicit': 9, 'optional': True}),
        ('enc-authorization-data', EncryptedData, {'explicit': 10, 'optional': True})
    ]


class KDCReq(Sequence):
    _fields = [
        ('pvno', Integer, {'explicit': 1}),
        ('msg-type', Integer, {'explicit': 2}),
        ('padata', make_sequence_of(PaData), {'explicit': 3, 'optional': True}),
        #		('padata', PaData, {'explicit': 3, 'optional': True}),
        ('req-body', KDCReqBody, {'explicit': 4}),
    ]


class KDCRep(Sequence):
    _fields = [
        ('pvno', Integer, {'explicit': 0}),
        ('msg-type', Integer, {'explicit': 1}),
        ('padata', make_sequence_of(PaData), {'explicit': 2, 'optional': True}),
        ('crealm', Realm, {'explicit': 3}),
        ('cname', PrincpalName, {'explicit': 4}),
        ('ticket', Ticket, {'explicit' : 5}),
        ('enc-part', EncryptedData, {'explicit': 6})
    ]


class KrbError(Sequence):
    explicit = (APPLICATION, 30)
    _fields = [
        ('pvno', Integer, {'explicit': 0}),
        ('msg-type', Integer, {'explicit': 1}),
        ('ctime', KerberosTime, {'explicit': 2, 'optional': True}),
        ('cusec', Microseconds, {'explicit': 3, 'optional': True}),
        ('stime', KerberosTime, {'explicit': 4}),
        ('susec', Microseconds, {'explicit': 5}),
        ('error-code', Integer, {'explicit': 6}),
        ('crealm', Realm, {'explicit': 7, 'optional': True}),
        ('cname', PrincpalName, {'explicit': 8, 'optional': True}),
        ('realm', Realm, {'explicit': 9}),
        ('sname', PrincpalName, {'explicit': 10}),
        ('e-text', KerberosString, {'explicit': 11, 'optional': True}),
        ('e-data', OctetString, {'explicit': 12, 'optional': True}),
    ]

class KDCBaseReply(Sequence):
    _fields = [
        ('pvno', Integer, {'explicit': 0}),
        ('msg-type', Integer, {'explicit': 1})
    ]


class TGSReq(KDCReq):
    explicit = (APPLICATION, 12)

class TGSRep(KDCRep):
    explicit = (APPLICATION, 13)

class ASReq(KDCReq):
    explicit = (APPLICATION, 10)

class ASRep(KDCRep):
    explicit = (APPLICATION, 11)

def make_kdcoptions():
    return KDCOptions({'forwardable', 'proxiable', 'renewable-ok'})

def make_asbody(username, domain):
    NT_PRINCIPAL = 1
    NT_SRV_INST = 2
    namestring_type = make_sequence_of(KerberosString)

    body = KDCReqBody()
    body['kdc-options'] = make_kdcoptions()

    cname = PrincpalName()
    cname_namestring = namestring_type()
    cname_namestring.append(username)

    cname['name-type'] = NT_PRINCIPAL
    cname['name-string'] = cname_namestring
    body['cname'] = cname

    body['realm'] = domain

    sname = PrincpalName()
    sname_namestring = namestring_type()
    sname_namestring.append('krbtgt')
    sname_namestring.append(domain)

    sname['name-type'] = NT_SRV_INST
    sname['name-string'] = sname_namestring
    body['sname'] = sname

    # from_t = KerberosTime()
    # body['from'] = from_t

    till_time = datetime.datetime.now() + datetime.timedelta(days=7)
    till = KerberosTime(till_time)
    body['till'] = till

    # rtime = KerberosTime()
    # body['rtime'] = rtime

    body['nonce'] = random.randint(0, 100000)

    etype = EType()
    for _ in [
        23, # ARCFOUR-HMAC-MD5
        -133, # ARCFOUR-HMAC-OLD
        -128, # ARCFOUR-MD4
        3, # DES-CBC-MD5
        1, # DES-CBC-CRC
        24, # ARCFOUR-HMAC-MD5-26
        -135 # ARCFOUR-HMAC-OLD-EXP
    ]:
        etype.append(_)
    body['etype'] = etype

    return body


KRB_AS_REQ = 10
KRB_AS_REP = 11
KRB_ERROR = 30

ERROR_PREAUTH_REQUIRED = 25
ERROR_PRINCIPAL_UNKNOWN = 6

import socket

def does_user_exist(username, domain, dc, port):
    as_requeset = ASReq()

    as_requeset['pvno'] = 5
    as_requeset['msg-type'] = KRB_AS_REQ

    as_body = make_asbody(username=username, domain=domain)

    as_requeset['req-body'] = as_body
    data = as_requeset.dump(force=True)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((dc, port))

        s.sendall(data)
        reply = s.recv(1024)

        tag = Any.load(reply).tag

        if tag == KRB_ERROR:
            err = KrbError.load(reply)
            error_code = err['error-code'].native
            if error_code == ERROR_PREAUTH_REQUIRED:
                return True
            elif error_code == ERROR_PRINCIPAL_UNKNOWN:
                return False
            else:
                print('unknown error code:', err['error-code'])
                return False

        return False
    finally:
        s.close()


from optparse import OptionParser
parser = OptionParser()

parser.add_option('-i', '--dcip', dest='dc', help='ip of domain controller')
parser.add_option('-f', '--file', dest='filename', help='username dict')
parser.add_option('-d', '--domain', dest='domain', help='Netbios name of domain')
parser.add_option('-p', '--port', dest='port', type='int', default=88, help='Netbios name of domain')

(options, args) = parser.parse_args()

for username in open(options.filename).read().splitlines():
    print(options.domain+'\\'+username, does_user_exist(username, options.domain, options.dc, options.port))