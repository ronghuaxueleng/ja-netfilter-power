# -*- coding: utf-8 -*-
import base64

from Crypto.Hash import SHA1, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.asn1 import DerSequence, DerObjectId, DerNull, DerOctetString
from Crypto.Util.number import ceil_div
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


# noinspection PyTypeChecker
def pkcs15_encode(msg_hash, emLen, with_hash_parameters=True):
    """
    Implement the ``EMSA-PKCS1-V1_5-ENCODE`` function, as defined
    :param msg_hash: hash object
    :param emLen: int
    :param with_hash_parameters: bool
    :return: An ``emLen`` byte long string that encodes the hash.
    """
    digestAlgo = DerSequence([DerObjectId(msg_hash.oid).encode()])

    if with_hash_parameters:
        digestAlgo.append(DerNull().encode())

    digest = DerOctetString(msg_hash.digest())
    digestInfo = DerSequence([
        digestAlgo.encode(),
        digest.encode()
    ]).encode()

    # We need at least 11 bytes for the remaining data: 3 fixed bytes and
    # at least 8 bytes of padding).
    if emLen < len(digestInfo) + 11:
        raise TypeError("Selected hash algorithm has a too long digest (%d bytes)." % len(digest))
    PS = b'\xFF' * (emLen - len(digestInfo) - 3)
    return b'\x00\x01' + PS + b'\x00' + digestInfo


certBase64 = """
MIIExTCCAq2gAwIBAgIUEE/E/uZeiRwV/mZt/+NbVmh6bS4wDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAwwNSmV0UHJvZmlsZSBDQTAeFw0yNDEyMTExNDAyNTFaFw0z
NDEyMTAxNDAyNTFaMCExHzAdBgNVBAMMFk1vWXVuby1mcm9tLTIwMjItMDctMjUw
ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC9NkRdkF1/UW4tKIcJYPKY
Jbs4452Qr+2XzHpJygYLa4MKbOMNJL0tFtrFB9tpxwg+2Pzkvu3GWQ3NXD/ETYed
K5he1lRo0jqIqbVKC428AW6i9Lb93XexEL6jsIER0dZxnQ7lSOt3kDQPvL8GBHVc
r21eNTGDwyM/zPk2zTrJGpjiuUDDq5csyV3ERCJm9pT7wmUd/sM+0cj/hLV/Vqw3
ibeKRFccJ7kzx9O9wtgRQLn6ugi85i9UzMljRAqxZc9of47wBW7M8egZ+KXw6FF3
MlvfjeSk2dlA7hFeW032uY8S4em0vFkGWIpJoiIniygRZoY4rHx3liTj3DzODM1p
Jm5bwzjadjM9uZaCZxf7i15VF3wM/gLAqPFpj89cx9QkxHSdZWrfg4bW7EIqoUCA
KxmQdWF4dHV0vMoFga4Du0xkUnLccW77EziH9dbgxBGX9iZm2JajDiYlVwc6LAj8
CtQ1Vv3w5cObB29o9vXM3+snS3cugEAWeH2qfSYKwBs+sw6y/W5dxwKzKRh8ORg5
M1nDst1EKvOhYTTx/lhx1XyXDHQ6yFJmNXqHbx4cn3GXE+v1BsHgI6nNZS0sEtKF
EPTP5iPU5fTpMnSmFfuMRt2oSqZubzX82au+DBKAkhzwA3hQnkxKY7lVOtQ/XecG
On0cqUx4Cf2wKv/5Bs+FCQIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQAxzWoMIr7c
VCDh0ZLj3BgE7SFNU5s7UB3F8tiRFpgCnTPL+iXYP8UaBS3ILfSVctlagA590TBe
2/IpAAfpGoowL4ERd4Ov8IDfs6flXx9Y4vVs6uV2Y2dzmZRbANalilTBjTsLmqJH
/BvMbAQl8BGwPUM8RjHm7Pg5XcDdKOmOY6jxhyxp6PUjyuap88lGD/V1sV72cpO0
3D2qUzHN5ZPhd9anJN+cns7pnfmzWLMSxL+x42HEeS8DmP55oSYXVNWw8qMVTnQ8
qfQ5scdfuksIkNlWiOnjufvI4E9XEuSVhE5PB+1IUiHfDP8LFsfXTPMRxNAlsZ2c
D6/hX/vH8fNKsaTsW9SJD4GDWSbElAGpijUWWVghK6eC9ehi8o6dDzBSZGH+uqjv
REQ/se/N6Lo5pDWTY7863eTL71usS8qaeCRAY2MHNo4DfRrkf412YzfP8oJUfZK1
Byq4X6k+ThUuLl4FIUI93cd8L0HchmQBi/8vrTzfymR93dbcY4JBzYIC2N5PX3OD
1pCfe9DwpqxWFsJfFXsdQFKLmfNK4loh2d8Wvu81qwya0wzlA4uWrzl7AvfyXKpL
BZpJU12ICSXtoPOkQ3lZhYJc9HrVD3QDwTIVWrCWZVSr266RzbTGkdrxZMoGipq+
8sDikIIwfGf75tWzDLRAVFTDOn+0VqvMgA==
"""
cert = x509.load_der_x509_certificate(base64.b64decode(certBase64))
public_key = cert.public_key()
sign = int.from_bytes(cert.signature, byteorder="big", )
print(f"sign:{sign}")

modBits = public_key.key_size
digest_cert = SHA256.new(cert.tbs_certificate_bytes)
r = int.from_bytes(pkcs15_encode(digest_cert, ceil_div(modBits, 8)), byteorder='big', signed=False)
print(f"result:{r}")

licenseId = 'ZCB571FZHV'
licensePart = '{"licenseId": "ZCB571FZHV", "licenseeName": "MoYuno", "assigneeName": "", "assigneeEmail": "", "licenseRestriction": "", "checkConcurrentUse": false, "products": [{"code": "PDB", "fallbackDate": "2030-12-31", "paidUpTo": "2030-12-31", "extended": true}, {"code": "PSI", "fallbackDate": "2030-12-31", "paidUpTo": "2030-12-31", "extended": true}, {"code": "PPC", "fallbackDate": "2030-12-31", "paidUpTo": "2030-12-31", "extended": true}, {"code": "PCWMP", "fallbackDate": "2030-12-31", "paidUpTo": "2030-12-31", "extended": true}, {"code": "PPS", "fallbackDate": "2030-12-31", "paidUpTo": "2030-12-31", "extended": true}, {"code": "PRB", "fallbackDate": "2030-12-31", "paidUpTo": "2030-12-31", "extended": true}, {"code": "II", "fallbackDate": "2030-12-31", "paidUpTo": "2030-12-31", "extended": false}, {"code": "PGO", "fallbackDate": "2030-12-31", "paidUpTo": "2030-12-31", "extended": true}, {"code": "PSW", "fallbackDate": "2030-12-31", "paidUpTo": "2030-12-31", "extended": true}, {"code": "PWS", "fallbackDate": "2030-12-31", "paidUpTo": "2030-12-31", "extended": true}], "metadata": "0120220701PSAN000005", "hash": "TRIAL:-594988122", "gracePeriodDays": 7, "autoProlongated": false, "isAutoProlongated": false}'

digest = SHA1.new(licensePart.encode('utf-8'))

with open('ca.key') as prifile:
    private_key = RSA.import_key(prifile.read())
    # 使用私钥对HASH值进行签名
    signature = pkcs1_15.new(private_key).sign(digest)

    sig_results = base64.b64encode(signature)
    licensePartBase64 = base64.b64encode(bytes(licensePart.encode('utf-8')))
    public_key.verify(
        base64.b64decode(sig_results),
        base64.b64decode(licensePartBase64),
        padding=padding.PKCS1v15(),
        algorithm=hashes.SHA1(),
    )
    result = licenseId + "-" + licensePartBase64.decode('utf-8') + "-" + sig_results.decode('utf-8') + "-" + certBase64
    print("激活码：")
    print(result)
