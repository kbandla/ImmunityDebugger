import unittest

from formulaparser import FormulaParser

class MockConstExpr:

    def __init__(self, val):
        self.val = val

class MockBinaryExpr:

    def __init__(self, lhs, rhs):
        self.lhs = lhs
        self.rhs = rhs

class MockEqExpr(MockBinaryExpr):
    pass

class MockNeExpr(MockBinaryExpr):
    pass

class MockLeExpr(MockBinaryExpr):
    pass

class MockBoolOrExpr(MockBinaryExpr):
    pass

class MockBoolAndExpr(MockBinaryExpr):
    pass

class MockSolver:

    def __init__(self):
        self.regs = {'EAX' : MockConstExpr(0x0),
                    'EBX' : MockConstExpr(0x1),
                    'ECX' : MockConstExpr(0x2),
        }

    def constExpr(self, val, width=32):
        return MockConstExpr(val)

    def leExpr(self, lhs, rhs):
        return MockLeExpr(lhs, rhs)

    def eqExpr(self, lhs, rhs):
        return MockEqExpr(lhs, rhs)
    
    def neExpr(self, lhs, rhs):
        return MockNeExpr(lhs, rhs)

    def boolAndExpr(self, lhs, rhs):
        return MockBoolAndExpr(lhs, rhs)

    def boolOrExpr(self, lhs, rhs):
        return MockBoolOrExpr(lhs, rhs)

class MockSequenceAnalyzer:

    def __init__(self):
        self.state=object()
        self.state.solver = MockSolver()

class TestFormulaParser(unittest.TestCase):

    def setUp(self):
        self.sa = MockSequenceAnalyzer()
        self.f_parser = FormulaParser()
        #self.f_parser.enable_debug(verbose=False)

    def testParseFormula_eq(self):
        expr = self.f_parser.parseFormula(self.sa, 'EAX <= EBX')
        self.assertTrue(isinstance(expr, MockLeExpr))
        self.assertTrue(isinstance(expr.lhs, MockConstExpr))
        self.assertEqual(expr.lhs.val, 0x0)
        self.assertTrue(isinstance(expr.rhs, MockConstExpr))
        self.assertEqual(expr.rhs.val, 0x1)

        self.assertEqual(len(self.f_parser.expr_stack), 0)
        self.assertEqual(len(self.f_parser.connective_stack), 0)
        self.assertEqual(len(self.f_parser.eq_symbol_stack), 0)
    
    def testParseFormula_connective(self):
        expr = self.f_parser.parseFormula(self.sa, 
                'EAX = ECX ^ ECX != 0x10')
        self.assertTrue(isinstance(expr, MockBoolAndExpr))
        self.assertTrue(isinstance(expr.lhs, MockEqExpr))
        self.assertTrue(isinstance(expr.rhs, MockNeExpr))
        
        eq_expr = expr.lhs
        self.assertTrue(isinstance(eq_expr, MockEqExpr))
        self.assertTrue(isinstance(eq_expr.lhs, MockConstExpr))
        self.assertEqual(eq_expr.lhs.val, 0x0)
        self.assertTrue(isinstance(eq_expr.rhs, MockConstExpr))
        self.assertEqual(eq_expr.rhs.val, 0x2)

        ne_expr = expr.rhs
        self.assertTrue(isinstance(ne_expr, MockNeExpr))
        self.assertTrue(isinstance(ne_expr.lhs, MockConstExpr))
        self.assertEqual(ne_expr.lhs.val, 0x2)
        self.assertTrue(isinstance(ne_expr.rhs, MockConstExpr))
        self.assertEqual(ne_expr.rhs.val, 0x10)

        self.assertEqual(len(self.f_parser.expr_stack), 0)
        self.assertEqual(len(self.f_parser.connective_stack), 0)
        self.assertEqual(len(self.f_parser.eq_symbol_stack), 0)

    def testCheckSyntax(self):
        valid = 'EAX = EDX'
        self.assertTrue(self.f_parser.check_syntax(valid)[0])
        valid = 'EAX = EDX ^ EDX != 0x10'
        self.assertTrue(self.f_parser.check_syntax(valid)[0])

        invalid = 'EAX = EC'
        self.assertFalse(self.f_parser.check_syntax(invalid)[0])
        invalid = 'EAX = EDX <= EDX != 0x10'
        self.assertFalse(self.f_parser.check_syntax(invalid)[0])

if __name__ == '__main__':
    unittest.main()

