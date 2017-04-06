import unittest
import array
import sys
import os
import ipaddranonymizer
import numpy as np

class TestIPAddrAnonymizer(unittest.TestCase):
    def setUp(self):
        print 'TestIPAddrAnonymizer:setup'
        self._obj = ipaddranonymizer.IPAddrAnonymizer()

    def tearDown(self):
        print 'TestIPAddrAnonymizer:tearDown'

    def testTruncation(self):
        input = 3221225985
        output = 12582914
        ret = self._obj.truncation(input,8)
        print "input:",input
        print "output:",ret
        self.assertEqual(ret,output)
        
    def testRandomPermutation(self):
        input = 3221225985
        output = 905380232
        self._obj.setRandomSeed(0)
        ret = self._obj.randomPermutation(input,4)
        print "input:",input
        print "output:",ret
        self.assertEqual(ret,output)
        

class TestCryptoPAnAnonymizer(unittest.TestCase):

    def setUp(self):
        print 'TestCryptoPAnAnonymizer:setUp'
        key = array.array('B',range(32))
        print 'key:',key
        self._cryptopan = ipaddranonymizer.CryptoPAnAnonymizer(key)

    def tearDown(self):
        print 'TestCryptoPAnAnonymizer:tearDown'

    def test_anonymize1(self):
        print "test anonymize #1"
        input = 3221225985
        output = 39476497
        ret = self._cryptopan.anonymize(input,4,32)
        print "input:",input
        print "output:",ret
        self.assertEqual(ret,output)


    def test_anonymize2(self):
        print "test anonymize #2"
        input = 3221225986
        output = 39476499
        ret = self._cryptopan.anonymize(input,4,32)
        print "input:",input
        print "output:",ret
        self.assertEqual(ret,output)

    def test_anonymize3(self):
        print "test anonymize #3"
        input = 42540766411282592856903984951653826561
        output = 294518360243080978531168246475884887552
        ret = self._cryptopan.anonymize(input,6,128)
        print "input:",input
        print "output:",ret
        self.assertEqual(ret,output)

    def test_anonymize4(self):
        print "test anonymize #4"
        input = 42540766411282592856903984951653826562
        output = 294518360243080978531168246475884887554
        ret = self._cryptopan.anonymize(input,6,128)
        print "input:",input
        print "output:",ret
        self.assertEqual(ret,output)

if __name__ == '__main__':
    unittest.main()
