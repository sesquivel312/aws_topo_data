import unittest
import binascii
import hashlib

import lib


class SigTests(unittest.TestCase):

    # constants from the test suite for sig version 4 docs
    REQ_DATE_TIME_TUP = ('20150830T123600Z', '20150830')
    REGION = 'us-east-1'
    SERVICE = 'service'
    KEY_ID = 'AKIDEXAMPLE'
    SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'
    SIGNED_HDRS_STR = 'host;x-amz-date'
    SCOPE_STR = '20150830/us-east-1/service/aws4_request'

    TEST_CANONICAL_REQ_PFX = """GET
/
Param1=value1&Param2=value2
host:example.amazonaws.com
x-amz-date:20150830T123600Z

host;x-amz-date"""

    TEST_REQ_BODY = ''

    EXP_CANONICAL_REQ = """GET
/
Param1=value1&Param2=value2
host:example.amazonaws.com
x-amz-date:20150830T123600Z

host;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"""

    # hash of cacnonical request above is (not currently used in tests
    # 816cd5b414d056048ba4f7c5386d6e0533120fb1fcfa93762cf0fc39e2cf19e0

    EXP_STR_TO_SIGN = """AWS4-HMAC-SHA256
20150830T123600Z
20150830/us-east-1/service/aws4_request
816cd5b414d056048ba4f7c5386d6e0533120fb1fcfa93762cf0fc39e2cf19e0"""

    EXP_SIG_KEY = '938127b5336810ddb6a5d6af445fcac9e371f9ed418ed386b022aed82901be75'

    EXP_SIG = 'b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500'

    EXP_AUTH_STR = 'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, ' \
                   'SignedHeaders=host;x-amz-date, ' \
                   'Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500'

    def test_gen_canonical_request(self):

        test_canonical_request = lib.generate_canonical_request(self.TEST_CANONICAL_REQ_PFX, self.TEST_REQ_BODY)

        self.assertEqual(self.EXP_CANONICAL_REQ, test_canonical_request)

    def test_gen_str_to_sign(self):

        scope_string, test_string_to_sign = lib.generate_string_to_sign(self.REGION, self.SERVICE, self.REQ_DATE_TIME_TUP,
                                                          self.EXP_CANONICAL_REQ)

        self.assertEqual(self.SCOPE_STR, scope_string)
        self.assertEqual(self.EXP_STR_TO_SIGN, test_string_to_sign)


    def test_gen_signing_key(self):

        test_signing_key = lib.generate_signing_key(self.SECRET_KEY, self.REQ_DATE_TIME_TUP,
                                                    self.REGION, self.SERVICE, hashlib.sha256)

        test_signing_key = binascii.hexlify(test_signing_key)

        self.assertEqual(self.EXP_SIG_KEY, test_signing_key)  # generate_signing_key returns a binary string

    def test_gen_sig(self):

        test_sig = lib.generate_signature(self.SECRET_KEY, self.EXP_STR_TO_SIGN, self.REQ_DATE_TIME_TUP,
                                          self.REGION, self.SERVICE)

        self.assertEqual(self.EXP_SIG, test_sig)

    def test_gen_auth_string(self):
        print self.EXP_AUTH_STR


if __name__ == '__main__':
    unittest.main()
