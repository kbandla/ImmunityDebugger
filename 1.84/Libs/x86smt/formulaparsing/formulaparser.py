from pyparsing import ParseException

from grammar import HEXNUM, EQ_SYMBOL, REGISTER, RELATION 
from grammar import MEMREF, FORMULA, CONNECTIVE
from grammar import equality_symbols, logical_connectives

class InvalidRelationalSymbolException(Exception):
    pass

class InvalidConnectiveSymbolException(Exception):
    pass

class FormulaParser:

    def __init__(self, debug_mode=False, verbose=False):
        self.debug_mode = debug_mode

        if self.debug_mode:
            self.enable_debug(verbose)

    def relationToExpr(self, r, lhs, rhs, signed=False):
        exp = None

        if r == '<':
            if signed:
                exp = self.solver.sltExpr(lhs, rhs)
            else:
                exp = self.solver.ltExpr(lhs, rhs)
        elif r == '>':
            if signed:
                exp = self.solver.sgtExpr(lhs, rhs)
            else:
                exp = self.solver.gtExpr(lhs, rhs)
        elif r == '=':
            exp = self.solver.eqExpr(lhs, rhs)
        elif r == '!=':
            exp = self.solver.neExpr(lhs, rhs)
        elif r == '<=':
            if signed:
                exp = self.solver.sleExpr(lhs, rhs)
            else:
                exp = self.solver.leExpr(lhs, rhs)
        elif r == '>=':
            if signed:
                exp = self.solver.sgeExpr(lhs, rhs)
            else:
                exp = self.solver.geExpr(lhs, rhs)
        else:
            raise InvalidRelationalSymbolException(r)

        return exp

    def connectiveToExpr(self, c, lhs, rhs):
        exp = None

        if c == '^':
            exp = self.solver.boolAndExpr(lhs, rhs)
        elif c == 'v':
            exp = self.solver.boolOrExpr(lhs, rhs)
        else:
            raise InvalidConnectiveSymbolException(c)

        return exp

    def createConstExpr(self, token):
        val = int(token[0], 16)
        self.expr_stack.append(self.solver.constExpr(val))
    
    def getRegisterExpr(self, token):
        self.expr_stack.append(self.sm.regs[token[0]])

    def createNewLogicExpr(self, token):
        self.connective_stack.append(token[0])

    def createEqSymbol(self, token):
        self.eq_symbol_stack.append(token[0])

    def createNewMemref(self, token):
        pass

    def createNewRelation(self, token):
        eq_symbol = self.eq_symbol_stack.pop() 
        rhs = self.expr_stack.pop()
        lhs = self.expr_stack.pop()
        self.expr_stack.append(self.relationToExpr(eq_symbol,
                    lhs, rhs))

    def createNewFormula(self, token):
        if len(self.connective_stack) > 0:
            # RELATION CONNECTIVE RELATION
            connective = self.connective_stack.pop()
            rhs = self.expr_stack.pop()
            lhs = self.expr_stack.pop()
            self.expr_stack.append(self.connectiveToExpr(connective,
                        lhs, rhs))

    def setupParseActions(self):
        HEXNUM.setParseAction(self.createConstExpr)
        REGISTER.setParseAction(self.getRegisterExpr)
        CONNECTIVE.setParseAction(self.createNewLogicExpr)
        EQ_SYMBOL.setParseAction(self.createEqSymbol)
        MEMREF.setParseAction(self.createNewMemref)
        RELATION.setParseAction(self.createNewRelation)
        FORMULA.setParseAction(self.createNewFormula)

    def clearParseActions(self):
        HEXNUM.setParseAction(lambda x:x)
        REGISTER.setParseAction(lambda x:x)
        CONNECTIVE.setParseAction(lambda x:x)
        EQ_SYMBOL.setParseAction(lambda x:x)
        MEMREF.setParseAction(lambda x:x)
        RELATION.setParseAction(lambda x:x)
        FORMULA.setParseAction(lambda x:x)

    def debugLog(self, x):
        print "DEBUG %s" % str(x)

    def enableDebug(self, verbose=False):
        self.debug_mode = True

        if verbose:
            HEXNUM.setDebug()
            REGISTER.setDebug()
            CONNECTIVE.setDebug()
            EQ_SYMBOL.setDebug()
            MEMREF.setDebug()
            RELATION.setDebug()
            FORMULA.setDebug()

        self.add_debug_actions()

    def add_debug_actions(self):
        HEXNUM.addParseAction(lambda x:self.debugLog(
                    "Hexnum %s" % str(x)))
        REGISTER.addParseAction(lambda x:self.debugLog(
                    "Register %s" % str(x)))
        CONNECTIVE.addParseAction(lambda x:self.debugLog(
                    "Connective %s" % str(x)))
        EQ_SYMBOL.addParseAction(lambda x:self.debugLog(
                    "Eqsymbol %s" % str(x)))
        MEMREF.addParseAction(lambda x:self.debugLog(
                    "Memref %s" % str(x)))
        RELATION.addParseAction(lambda x:self.debugLog(
                    "Relation %s" % str(x)))
        FORMULA.addParseAction(lambda x:self.debugLog(
                    "Formula %s" % str(x)))

    def check_syntax(self, f_str):
        self.clearParseActions()

        if self.debug_mode:
            self.addDebugActions()

        try:
            FORMULA.parseString(f_str)
        except ParseException, e:
            return (False, str(e))

        return (True, None)

    def parseFormula(self, state_machine, f_str):
        self.sm = state_machine
        self.solver = self.sm.solver

        self.connective_stack = []
        self.eq_symbol_stack = []
        self.expr_stack = []

        self.setupParseActions()
        FORMULA.parseString(f_str)

        return self.expr_stack.pop()

