#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Created by iFantastic on 19-1-21
import base64
import rsa

public_key_str = """-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAJDpc5P6/FVcZ/L2f9lkEV8ifs+KRRyoOB9PeaYgz23k3jGXPB4pJnAV
g70yvkecXCodQjSI4/AXhIM3rpV66ybjiLHe1ST3cDu2UvP6l5z0W7S4C/R5RKMa
a9+57I+m+1Mf7YGm8VT79+Nq9gFwpPxfTTs82SAFLZvBd5aGufZdAgMBAAE=
-----END RSA PUBLIC KEY-----"""

private_key_str = """-----BEGIN RSA PRIVATE KEY-----
MIICYQIBAAKBgQCQ6XOT+vxVXGfy9n/ZZBFfIn7PikUcqDgfT3mmIM9t5N4xlzwe
KSZwFYO9Mr5HnFwqHUI0iOPwF4SDN66Veusm44ix3tUk93A7tlLz+pec9Fu0uAv0
eUSjGmvfueyPpvtTH+2BpvFU+/fjavYBcKT8X007PNkgBS2bwXeWhrn2XQIDAQAB
AoGAAsipUr9wl4c17AH2RMvaVZSJER2b5EgLA/b35EwfEAJkjllUa1PpDCAtrrXJ
2ABV+O0k93NlxZf+ELNCH7Br40ORh+Ur4cGPhwcaKlco3/4nF5Hc8l0+IMCO5N/9
Jiu+tcLAV2EhwYWrb7E6rCjDEDP0X48odDB3VRe4mq+TbOECRQDyFyqoHiLuueHX
5b9MjmyF48gUiq6njduBcaLwAdjkWjzcDPrcZZq0kmfXRpBzIyiDzHNd+XG78Rvs
s5iom739dSDYyQI9AJk86mPADqWt3tl3H6T5c0kBu6/vJNijWmULdtlSCJZINKL6
eGll+nX6Mq/lw+KCcPJnY5KZdx761jOO9QJFAM4/gm38TtKHtqsS5ym35SkkaF9n
z2icaLgdMi27xSa24kavIEIIpgbU/HbhfUs6VtgCpP8Y9xahUaMVVye+l9yJn1RR
Ajwb+CxoDJQf1X6Jft69w/Iw7yoM0L+O8zH6o38L55c9puxEmycDRePTSNmblXqN
i3WGKSzZgz1k4C/ctUkCRQCYdZlm8f99cWPWrmRtA+exWvjD8lK9bA5mxwW7Cp+P
e5iXMLuqb0xeMbt6YRMN/js0CeeQA8X1r6XjdQseujZHCAu1sw==
-----END RSA PRIVATE KEY-----"""

private_key = rsa.PrivateKey.load_pkcs1(private_key_str)
public_key = rsa.PublicKey.load_pkcs1(public_key_str)


def rsa_encrypt(source_msg):
    source_msg = source_msg.encode('utf-8')
    length = len(source_msg)
    default_length = 117
    if length < default_length:
        return base64.encodestring(rsa.encrypt(source_msg, public_key))
    offset = 0
    res = []
    while length - offset > 0:
        if length - offset > default_length:
            res.append(base64.encodestring(rsa.encrypt(source_msg[offset:offset + default_length], public_key)))
        else:
            res.append(base64.encodestring(rsa.encrypt(source_msg[offset:], public_key)))
        offset += default_length
    return "\t".join(res)


def rsa_decrypt(encrypt_str):
    encrypt_lists = encrypt_str.split("\t")
    content = []
    for message in encrypt_lists:
        content.append(rsa.decrypt(base64.decodestring(message), private_key))
    return "".join(content)


if __name__ == '__main__':
    source_src = '{"list": ["39.96.0.0/13","39.104.0.0/14","39.104.0.0/14","39.104.0.0/14","39.108.0.0/16","39.108.0.0/16","39.108.0.0/16","42.96.128.0/17"]}'
    enc = rsa_encrypt(source_src)
    print enc
    dec = rsa_decrypt(enc)
    print dec
    print source_src == dec
