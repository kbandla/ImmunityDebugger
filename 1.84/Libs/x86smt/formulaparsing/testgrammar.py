import unittest
from pyparsing import ParseException

from grammar import HEXNUM, EQ_SYMBOL, REGISTER, RELATION
from grammar import MEMREF, CONNECTIVE, FORMULA

class TestGrammar(unittest.TestCase):
    
    def testHEXNUM(self):
        HEXNUM.parseString('0x123abCD')
        HEXNUM.parseString('123abCD')

    def testEQ_SYMBOL(self):
        EQ_SYMBOL.parseString('<=')
        EQ_SYMBOL.parseString('=')
        self.assertRaises(ParseException, EQ_SYMBOL.parseString, '!')

    def testREGISTER(self):
        REGISTER.parseString('EAX')
        REGISTER.parseString('eax')

    def testCONNECTIVE(self):
        CONNECTIVE.parseString('v')

    def testMEMREF(self):
        MEMREF.parseString('[EAX]')
        MEMREF.parseString('[[EAX]]')
        MEMREF.parseString('[[EAX+4]]')
        MEMREF.parseString('[[EAX+EBX]]')
        MEMREF.parseString('[0x50+4]')
        MEMREF.parseString('[0x50]')

    def testRELATION(self):
        RELATION.parseString('EAX <= EBX')
        RELATION.parseString('EAX = 0x50')
        #RELATION.parseString('(EAX = 0x50)')
        self.assertRaises(ParseException, 
                RELATION.parseString, '50 <= EAX')

    def testFORMULA(self):
        FORMULA.parseString('EAX <= EBX ^ ECX = 50')
        FORMULA.parseString('EAX <= EBX')
        FORMULA.parseString('EAX = 0x50')
        #FORMULA.parseString('(EAX = 0x50)')
        self.assertRaises(ParseException, 
                FORMULA.parseString, '50 <= EAX')
        #FORMULA.parserString('!(EAX <= EBX ^ ECX = 50)')
        #FORMULA.parseString('(EAX <= EBX) ^ (ECX = 50)')
        #FORMULA.parseString('(EAX <= EBX)) ^ (ECX = 50)')

if __name__ == '__main__':
    unittest.main()

