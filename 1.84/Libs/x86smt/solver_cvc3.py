from ctypes import *
from sys import platform,exit
from binascii import crc32
import os.path

class Solver(object):
    
    #kind of expressions
    _TRUE_EXPR        = 0x1
    _FALSE_EXPR       = 0x2
    _RATIONAL_EXPR    = 0x3
    _BVCONST          = 0x50
    _BOOLEAN          = 0x67
    _EQ               = 0x6D
    _NEQ              = 0x6E
    _DISTINCT         = 0x6F
    _NOT              = 0x70
    _AND              = 0x71
    _OR               = 0x72
    _XOR              = 0x73
    _IFF              = 0x74
    _IMPLIES          = 0x75
    _ITE              = 0x79
    _FORALL           = 0x7A
    _EXISTS           = 0x7B
    _APPLY            = 0x7D
    _BOUND_VAR        = 0x0AC
    _LAMBDA           = 0x0B6
    _UCONST           = 0x0BA
    _SKOLEM_VAR       = 0x0BE
    _BITVECTOR        = 0x1F40
    _CONCAT           = 0x1F41
    _EXTRACT          = 0x1F42
    _BOOLEXTRACT      = 0x1F43
    _LEFTSHIFT        = 0x1F44
    _CONST_WIDTH_LEFTSHIFT  = 0x1F45
    _RIGHTSHIFT       = 0x1F46
    _BVSHL            = 0x1F47
    _BVLSHR           = 0x1F48
    _BVASHR           = 0x1F49
    _SX               = 0x1F4A
    _BVREPEAT         = 0x1F4B
    _BVZEROEXTEND     = 0x1F4C
    _BVROTL           = 0x1F4D
    _BVROTR           = 0x1F4E
    _BVAND            = 0x1F4F
    _BVOR             = 0x1F50
    _BVXOR            = 0x1F51
    _BVXNOR           = 0x1F52
    _BVNEG            = 0x1F53
    _BVNAND           = 0x1F54
    _BVNOR            = 0x1F55
    _BVCOMP           = 0x1F56
    _BVUMINUS         = 0x1F57
    _BVPLUS           = 0x1F58
    _BVSUB            = 0x1F59
    _BVMULT           = 0x1F5A
    _BVUDIV           = 0x1F5B
    _BVSDIV           = 0x1F5C
    _BVUREM           = 0x1F5D
    _BVSREM           = 0x1F5E
    _BVSMOD           = 0x1F5F
    _BVLT             = 0x1F60
    _BVLE             = 0x1F61
    _BVGT             = 0x1F62
    _BVGE             = 0x1F63
    _BVSLT            = 0x1F64
    _BVSLE            = 0x1F65
    _BVSGT            = 0x1F66
    _BVSGE            = 0x1F67

    def __init__(self, manualInitialization=False):
        self.DEBUG = False
        self.vc = False
        self.flags = None

        self.tryLoadDLL("libgmp-10.dll")
        self.CVC = self.tryLoadDLL("libcvc3.2.1.1.dll")
            
        if not self.CVC:
            raise Exception, "failed to init CVC3 library"

        self.vc_exprString = self.CVC.vc_exprString
        self.vc_typeString = self.CVC.vc_typeString
        self.vc_getKindString = self.CVC.vc_getKindString
        self.vc_getName = self.CVC.vc_getName
        self.vc_getUid = self.CVC.vc_getUid
        self.vc_exprString.restype = \
            self.vc_typeString.restype = \
            self.vc_getName.restype = \
            self.vc_getUid.restype = \
            self.vc_getKindString.restype = c_char_p

        self.resetErrorStatus()

        if not manualInitialization:
            self.flags = self.createFlags()
            self.createValidityChecker(self.flags)
    
    def tryLoadDLL(self, name):
        try:
            return CDLL(os.path.join("Libs","x86smt",name))
        except WindowsError:
            try:
                return CDLL(name)
            except WindowsError:
                return None
            
    def initCommonTypes(self):
        self.bv64bits=self.bvType(64)
        self.bv32bits=self.bvType(32)
        self.bv16bits=self.bvType(16)
        self.bv8bits=self.bvType(8)
        self.booltype=self.boolType()
        self.true=self.trueExpr()
        self.false=self.falseExpr()

    def __del__(self):
        if self.vc:
            self.CVC.vc_destroyValidityChecker(self.vc)
            self.vc=None
        if self.flags:
            self.deleteFlags(self.flags)
            self.flags=None

    def resetErrorStatus(self):
        self.CVC.vc_reset_error_status()

    def createValidityChecker(self, flags=0):
        self.vc = self.CVC.vc_createValidityChecker(flags)
        if self.get_error():
            raise Exception, "failed initializing the Validity Checker"
        self.initCommonTypes()

    #Flags related functions
    def createFlags(self):
        return self.CVC.vc_createFlags() | self.get_error()

    def deleteFlags(self, flags):
        self.CVC.vc_deleteFlags(flags) | self.get_error()

    def setBoolFlag(self, flags, name, val):
        self.CVC.vc_setBoolFlag(flags, create_string_buffer(name), val) | self.get_error()

    def setIntFlag(self, flags, name, val):
        self.CVC.vc_setIntFlag(flags, create_string_buffer(name), val) | self.get_error()

    def setStringFlag(self, flags, name, val):
        self.CVC.vc_setStringFlag(flags, create_string_buffer(name), create_string_buffer(val)) | self.get_error()

    def setStrSeqFlag(self, flags, name, string, val):
        self.CVC.vc_setStrSeqFlag(flags, create_string_buffer(name), create_string_buffer(string), val) | self.get_error()

    #Validity checking functions
    #check CVC user manual to use this

    def assertFormula(self, exp):
        """
        Assert a new formula in the current context.
        This creates the assumption e |- e.  The formula must have Boolean type.
        """
        self.CVC.vc_assertFormula(self.vc, exp) | self.get_error()

    def queryFormula(self, exp):
        """
        Check validity of e in the current context.
        If it returns VALID, the scope and context are the same
        as when called.  If it returns INVALID, the context will be one which
        falsifies the query.  If it returns UNKNOWN, the context will falsify the
        query, but the context may be inconsistent.  Finally, if it returns
        ABORT, the context will be one which satisfies as much as possible.
        SATISFIABLE/INVALID = 0
        UNSATISFIABLE/VALID = 1
        ABORT = 2
        UNKNOWN = 3
        """
        return self.CVC.vc_query(self.vc, exp) | self.get_error()

    def checkUnsat(self, exp):
        """
        Check satisfiability of the expr in the current context.
        Equivalent to query(!e)
        """
        return self.queryFormula(self.boolNotExpr(exp))

    def checkSat(self, exp):
        return not self.checkUnsat(exp)

    def checkContinue(self):
        """
        Get the next model. 
        This method should only be called after a query which returns INVALID. Its return values are as for query().
        """
        return self.CVC.vc_checkContinue(self.vc) | self.get_error()

    def restart(self, exp):
        """
        Restart the most recent query with e as an additional assertion.
        This method should only be called after a query which returns INVALID. Its return values are as for query().
        """
        return self.CVC.vc_restart(self.vc, exp) | self.get_error()

    def returnFromCheck(self):
        """
        Returns to context immediately before last invalid query.
        This method should only be called after a query which returns false.
        """
        self.CVC.vc_returnFromCheck(self.vc) | self.get_error()

    def getCounterExample(self):
        """
        Return a list of internal assumptions that make the queried formula false.
        This method should only be called after a query which returns
        false.  It will try to return the simplest possible subset of
        the internal assumptions sufficient to make the queried expression
        false.
        """
        size = pointer(c_ulong(0))
        assumptions = self.CVC.vc_getCounterExample(self.vc, size) | self.get_error()
        assumptions = cast(assumptions, POINTER(c_ulong))
        ret = []
        for x in range(0,size[0]):
            ret.append(assumptions[x])
        return ret

    def getConcreteModel(self):
        """
        Will assign concrete values to all user created variables
        """
        size = pointer(c_ulong(0))

        #this push/pop protect us from this function adding the needed assumptions to falsify the context
        #this way we can call getConcreteModel multiple times (for example after checkContinue)
        self.push()
        assumptions = self.CVC.vc_getConcreteModel(self.vc, size) | self.get_error()
        self.pop()
        assumptions = cast(assumptions, POINTER(c_ulong))
        ret = []
        for x in range(0,size[0]):
            ret.append(assumptions[x])
        return ret

    def getUserAssumptions(self):
        """
        Get assumptions made by the user in this and all previous contexts.
        User assumptions are created either by calls to assertFormula or by a
        call to query.  In the latter case, the negated query is added as an
        assumption.
        """
        size = pointer(c_ulong(0))
        assumptions = self.CVC.vc_getUserAssumptions(self.vc, size) | self.get_error()
        assumptions = cast(assumptions, POINTER(c_ulong))
        ret = []
        for x in range(0,size[0]):
            ret.append(assumptions[x])
        return ret

    def getInternalAssumptions(self):
        """
        Get assumptions made internally in this and all previous contexts.
        Internal assumptions are literals assumed by the sat solver.
        """
        size = pointer(c_ulong(0))
        assumptions = self.CVC.vc_getInternalAssumptions(self.vc, size) | self.get_error()
        assumptions = cast(assumptions, POINTER(c_ulong))
        ret = []
        for x in range(0,size[0]):
            ret.append(assumptions[x])
        return ret

    def getAssumptions(self):
        """
        Get all assumptions made in this and all previous contexts.
        """
        size = pointer(c_ulong(0))
        assumptions = self.CVC.vc_getAssumptions(self.vc, size) | self.get_error()
        assumptions = cast(assumptions, POINTER(c_ulong))
        ret = []
        for x in range(0,size[0]):
            ret.append(assumptions[x])
        return ret

    def getAxioms(self, exp):
        size = pointer(c_ulong(0))
        axioms = self.CVC.vc_getAxioms(exp, size) | self.get_error()
        axioms = cast(axioms, POINTER(c_ulong))
        ret = []
        for x in range(0,size[0]):
            ret.append(axioms[x])
        return ret

    def getIndex(self, exp):
        return self.CVC.vc_getIndex(exp) | self.get_error()

    def getExistential(self, exp):
        return self.CVC.vc_getExistential(exp) | self.get_error()

    def getNumVars(self, exp):
        return self.CVC.vc_getNumVars(exp) | self.get_error()

    def getVar(self, exp, ind):
        return self.CVC.vc_getVar(exp, ind) | self.get_error()

    def getArity(self, exp):
        return self.CVC.vc_arity(exp) | self.get_error()

    def getChild(self, exp, ind):
        return self.CVC.vc_getChild(exp, ind) | self.get_error()

    def getBody(self, exp):
        return self.CVC.vc_getBody(exp) | self.get_error()

    def getKind(self, exp):
        return self.CVC.vc_getKind(exp) | self.get_error()

    def getClosure(self):
        return self.CVC.vc_getClosure(self.vc) | self.get_error()

    def isClosure(self, exp):
        """
        True if Expr is of kind EXISTS/FORALL/LAMBDA
        """
        return self.CVC.vc_isClosure(exp) | self.get_error()

    def isSkolem(self, exp):
        return self.CVC.vc_isSkolem(exp) | self.get_error()

    def getBoundIndex(self, exp):
        """
        it gets the bound variable index from where this Skolem variable was created.

        """
        return self.CVC.vc_getBoundIndex(exp) | self.get_error()
    
    def getFunction(self, exp):
        return self.CVC.vc_getFun(self.vc, exp) | self.get_error()
        
    def incomplete(self):
        """
        Returns a string of reasons for incompleteness if last query() was imprecise or False if not.
        """
        reasons = self.CVC.vc_incomplete(self.vc) | self.get_error()
        if not reasons:
            return False
        return string_at(reasons)

    def getProof(self):
        """
        Returns the proof term for the last proven query.
        The proofs flag must be on in order to use this.
        """
        return self.CVC.vc_getProof(self.vc) | self.get_error()

    #Context methods
    def stackLevel(self):
        return self.CVC.vc_stackLevel(self.vc) | self.get_error()

    def push(self):
        return self.CVC.vc_push(self.vc) | self.get_error()

    def pop(self):
        return self.CVC.vc_pop(self.vc) | self.get_error()

    def popto(self, level):
        return self.CVC.vc_popto(self.vc, level) | self.get_error()

    #Misc functions
    def deleteExpr(self,exp):
        self.CVC.vc_deleteExpr(exp)

    def deleteVector(self,vec):
        self.CVC.vc_deleteVector(vec)

    def importExpr(self, exp):
        return self.CVC.vc_importExpr(self.vc, exp) | self.get_error()

    #returns a simplified Expr
    def simplify(self, exp):
        return self.CVC.vc_simplify(self.vc,exp) | self.get_error()

    def parseFile(self, filename):
        self.CVC.vc_getProofOfFile(self.vc, create_string_buffer(filename)) | self.get_error()

    #returns a new Bit-Vector Type of <bits> bits
    def bvType(self, bits=32):
        return self.CVC.vc_bvType(self.vc, bits) | self.get_error()

    #returns a new Array Type with indexes of type indexType and values of type valueType
    def arrayType(self, indexType, valueType):
        return self.CVC.vc_arrayType(self.vc, indexType, valueType) | self.get_error()
    
    def boolType(self):
        return self.CVC.vc_boolType(self.vc) | self.get_error()

    def boundVarExpr(self, name, uid, vartype=None):
        if vartype == None:
            vartype = self.bv32bits
        return self.CVC.vc_boundVarExpr(self.vc, create_string_buffer(name), create_string_buffer(uid), vartype) | self.get_error()
    
    #returns a variable Expr
    def varExpr(self, name, vartype=None):
        if vartype == None or vartype == 32:
            vartype = self.bv32bits
        elif vartype == 8:
            vartype = self.bv8bits
        elif vartype == 16:
            vartype = self.bv16bits
        elif vartype < 0x1000:
            vartype = self.bvType(vartype)
        return self.CVC.vc_varExpr(self.vc, create_string_buffer(name),vartype) | self.get_error()

    #returns a variable Expr initialized with a given Expr
    def varDefExpr(self, name, definition, vartype=None):
        if vartype == None:
            vartype = self.bv32bits
        return self.CVC.vc_varExprDef(self.vc, create_string_buffer(name),vartype,definition) | self.get_error()

    def createTypeFromString(self, typename):
        if "BOOL" in typename:
            return self.booltype
        elif "BITVECTOR" in typename:
            bits=int(typename.replace("BITVECTOR(","").replace(")",""))
            return self.bvType(bits)
        else:
            raise Exception, "dont know how to interpret type string: %s"%typename
    
    def lookupVar(self, name):
        """
        Returns a 2-tuple with the expr and type of a variable
        """
        vartype=pointer(c_ulong(0))
        exp=self.CVC.vc_lookupVar(self.vc, create_string_buffer(name),vartype) | self.get_error()
        if not exp:
            return False
        return (exp, vartype[0])

    def get_error(self):
        errflag=self.CVC.vc_get_error_status()

        if errflag == 1:
            return 0
        else:
            errstr=string_at(self.CVC.vc_get_error_string())
            if self.DEBUG:
                tmp = "%s\nError Number:%x"%(errstr, errflag)
                print tmp
                exit(errflag)
            else:
                raise Exception, (errstr,"%x"%errflag)

    #Utils
    def compareExpr(self, exp1, exp2):
        """
        Returns True if exp1 and exp2 are PROVEN to be equal, returns FALSE in any other case.
        """

        type1=self.typeStringFromExpr(exp1)
        type2=self.typeStringFromExpr(exp2)

        if type1 != type2:
            raise Exception, "Cannot compare two expressions of different types"

        if "BOOLEAN" in type1:
            query = self.iffExpr(exp1,exp2)
        else:
            query = self.eqExpr(exp1,exp2)
        self.push()
        res=self.queryFormula(query)
        self.pop()
        if res == 0:
            return False
        elif res == 1: #VALID ANSWER
            return True
        else:
            return None

    def exprFromString(self, str):
        return self.CVC.vc_exprFromString(self.vc, create_string_buffer(str)) | self.get_error()

    def exprFromStringAndLang(self, str, lang):
        """
        This receives a list of commands, not formulas.
        """
        
        return self.CVC.vc_exprFromStringAndLang(self.vc, create_string_buffer(str), lang) | self.get_error()

    def exprString(self, exp, lang=0):
        """
        InputLanguage: 0 - PRESENTATION (CVC3 format)
                       1 - SMTLIB
                       2 - LISP
                       3 - AST
                       4 - SIMPLIFY
                       5 - TPTP
        """
        return self.vc_exprString(exp, lang)

    def getType(self, exp):
        return self.CVC.vc_getType(self.vc, exp) | self.get_error()

    def getName(self, exp):
        return self.vc_getName(exp)
    
    def getUid(self, exp):
        return self.vc_getUid(exp)

    def typeString(self, t):
        return self.vc_typeString(t)

    def typeStringFromExpr(self, exp):
        return self.typeString(self.getType(exp))

    def getBitSizeFromExpr(self, exp):
        tmp=self.typeStringFromExpr(exp)
        if "BITVECTOR" not in tmp:
            return None
        return int(tmp.replace("BITVECTOR(","")[0:-1])

    def getKindString(self, kind):
        return self.vc_getKindString(self.vc, kind)

    def kindString(self, exp):
        return self.getKindString(self.getKind(exp))

    def getBoolFromBitvector(self, exp):
        ifpart=self.gtExpr(exp, self.constExpr(0, self.getBitSizeFromExpr(exp)))
        thenpart=self.true
        elsepart=self.false
        return self.iteExpr(ifpart, thenpart, elsepart)

    def getBitvectorFromBool(self, exp, bits=1):
        """
        returns a BV with a 0 or 1 given a BOOL expresion
        """

        ifpart=exp
        thenpart=self.constExpr(1,bits)
        elsepart=self.constExpr(0,bits)
        return self.iteExpr(ifpart, thenpart, elsepart)
    
    def skolemizeVar(self, exp, idx):
        return self.CVC.vc_skolemize_var(exp, idx) | self.get_error()
    
    def skolemize(self, exp, boundVars, skolemVars):
        if len(boundVars) != len(skolemVars):
            raise Exception, "len(boundVars) != len(skolemVars)"
        
        arr1 = (c_ulong * len(boundVars))()
        c=0
        for x in boundVars:
            arr1[c] = x
            c+=1
        arr2 = (c_ulong * len(skolemVars))()
        c=0
        for x in skolemVars:
            arr2[c] = x
            c+=1
        
        return self.CVC.vc_skolemize(exp, arr1, arr2, len(boundVars)) | self.get_error()
    
    def getInt(self, exp):
        """
        get an Integer out of a rational expression.
        """
        return self.CVC.vc_getInt(exp) | self.get_error()

    #Logic functions
    def impliesExpr(self, hyp, concl):
        return self.CVC.vc_impliesExpr(self.vc, hyp, concl) | self.get_error()

    def iffExpr(self, exp1, exp2):
        return self.CVC.vc_iffExpr(self.vc, exp1, exp2) | self.get_error()

    def distinctExpr(self, arr_expr):
        """
        Create an expression asserting that all the children are different.
        receives a list of Expr that can be BV or BOOLEAN
        """
        arr = (c_ulong * len(arr_expr))()
        c=0
        for x in arr_expr:
            arr[c] = x
            c+=1

        return self.CVC.vc_distinctExpr(self.vc, arr, len(arr_expr)) | self.get_error()

    def forallExpr(self, Bvars, exp):
        """
        FORALL (Bvars): exp
        Bvars is a list of Expr
        """
        arr = (c_ulong * len(Bvars))()
        c=0
        for x in Bvars:
            arr[c] = x
            c+=1

        return self.CVC.vc_forallExpr(self.vc, arr, len(Bvars), exp) | self.get_error()

    def existsExpr(self, Bvars, exp):
        """
        EXISTS (Bvars): exp
        Bvars is a list of Expr
        """
        arr = (c_ulong * len(Bvars))()
        c=0
        for x in Bvars:
            arr[c] = x
            c+=1

        return self.CVC.vc_existsExpr(self.vc, arr, len(Bvars), exp) | self.get_error()

    def lambdaExpr(self, Bvars, exp):
        """
        LAMBDA (Bvars): exp
        Bvars is a list of Expr
        """
        arr = (c_ulong * len(Bvars))()
        c=0
        for x in Bvars:
            arr[c] = x
            c+=1

        return self.CVC.vc_lambdaExpr(self.vc, len(Bvars), arr, exp) | self.get_error()
    
    def iteExpr(self, ifpart, thenpart, elsepart):
        return self.CVC.vc_iteExpr(self.vc, ifpart, thenpart, elsepart) | self.get_error()

    def trueExpr(self):
        return self.CVC.vc_trueExpr(self.vc) | self.get_error()

    def falseExpr(self):
        return self.CVC.vc_falseExpr(self.vc) | self.get_error()

    def boolNotExpr(self, exp):
        return self.CVC.vc_notExpr(self.vc, exp) | self.get_error()

    def boolAndExpr(self, exp1, exp2):
        return self.CVC.vc_andExpr(self.vc, exp1, exp2) | self.get_error()

    def boolOrExpr(self, exp1, exp2):
        return self.CVC.vc_orExpr(self.vc, exp1, exp2) | self.get_error()

    def boolXorExpr(self, exp1, exp2):
        #p xor q = not(p and q) and (p or q)
        return self.boolAndExpr(self.boolNotExpr(self.boolAndExpr(exp1, exp2)), self.boolOrExpr(exp1, exp2))
    
    #Order functions
    def ltExpr(self, exp1, exp2):
        return self.CVC.vc_bvLtExpr(self.vc, exp1, exp2) | self.get_error()

    def leExpr(self, exp1, exp2):
        return self.CVC.vc_bvLeExpr(self.vc, exp1, exp2) | self.get_error()

    def gtExpr(self, exp1, exp2):
        return self.CVC.vc_bvGtExpr(self.vc, exp1, exp2) | self.get_error()

    def geExpr(self, exp1, exp2):
        return self.CVC.vc_bvGeExpr(self.vc, exp1, exp2) | self.get_error()

    def sltExpr(self, exp1, exp2):
        return self.CVC.vc_bvSLtExpr(self.vc, exp1, exp2) | self.get_error()

    def sleExpr(self, exp1, exp2):
        return self.CVC.vc_bvSLeExpr(self.vc, exp1, exp2) | self.get_error()

    def sgtExpr(self, exp1, exp2):
        return self.CVC.vc_bvSGtExpr(self.vc, exp1, exp2) | self.get_error()

    def sgeExpr(self, exp1, exp2):
        return self.CVC.vc_bvSGeExpr(self.vc, exp1, exp2) | self.get_error()

    def eqExpr(self, exp1, exp2):
        return self.CVC.vc_eqExpr(self.vc, exp1, exp2) | self.get_error()

    def neExpr(self, exp1, exp2):
        return self.boolNotExpr(self.eqExpr(exp1, exp2))

    #Bit-Vector functions
    def UConstFromExpr(self, exp):
        """return an unsigned long from a CONSTANT BITVECTOR expression"""
        if self.getKind(exp) != self._BVCONST:
            return None
        tmp = int(self.exprString(exp)[4:], 2)
        return tmp

    def constExpr(self, num, bits=32):
        num=num % (1<<bits)
        bin="".join([str((num >> y) & 1) for y in range(bits-1, -1, -1)])
        return self.CVC.vc_bvConstExprFromStr(self.vc, bin) | self.get_error()

    def concatExpr(self, exp1, exp2):
        return self.CVC.vc_bvConcatExpr(self.vc, exp1, exp2) | self.get_error()

    def extractExpr(self, exp, start, end):
        """
        NOTE: 0 here is the LEAST SIGNIFICANT BIT
        NOTE2: limits are included. ex: extract(start=0, end=1) extracts 2bits
        """
        return self.CVC.vc_bvExtract(self.vc, exp, end, start) | self.get_error()

    def boolExtractExpr(self, exp, bit):
        """
        NOTE: 0 here is the LEAST SIGNIFICANT BIT
        """

        return self.CVC.vc_bvBoolExtract(self.vc, exp, bit) | self.get_error()

    def signExtendExpr(self, exp, bits):
        return self.CVC.vc_bvSignExtend(self.vc, exp, bits) | self.get_error()

    def zeroExtendExpr(self, exp, bits):
        addsize = bits - self.getBitSizeFromExpr(exp)
        if addsize > 0:
            return self.concatExpr(self.constExpr(0, addsize), exp)
        else:
            return exp #avoid unnecessary expression

    #the <bits> here might be an expression or a constant amount
    def leftRotateExpr(self, exp, bits):
        finalsize = self.getBitSizeFromExpr(exp)
        if bits < 0x100:
            #this is a constant value
            bits=bits%finalsize
            if not bits:
                return exp

            return self.concatExpr(self.extractExpr(exp,0,finalsize-1-bits), self.extractExpr(exp,finalsize-bits,finalsize-1))

        bits_size=self.getBitSizeFromExpr(bits)
        bits=self.simplify(self.andExpr(bits,self.constExpr(31, bits_size)))
        if self.getKind(bits) == self._BVCONST:
            tmp=self.UConstFromExpr(bits)
            return self.leftRotateExpr(exp, tmp)

        for x in range(finalsize,-1,-1):
            if x != finalsize:
                ifpart=self.eqExpr(bits, self.constExpr(x, bits_size))
                if x == 0:
                    thenpart=exp
                else:
                    thenpart=self.concatExpr(self.extractExpr(exp,0,finalsize-1-x), self.extractExpr(exp,finalsize-x,finalsize-1))
                ite = self.iteExpr(ifpart, thenpart, elsepart)
                elsepart = ite
            else:
                elsepart = self.constExpr(0, finalsize)

        return ite | self.get_error()

    #the <bits> here might be an expression or a constant amount
    def leftShiftExpr(self, exp, bits, finalsize=None):
        #this code was copied almost verbatim from the c_interface file
        if not finalsize:
            finalsize=self.getBitSizeFromExpr(exp)

        if bits < 0x100:
            #this is a constant value, use the static version
            return self.extractExpr(self.CVC.vc_bvLeftShiftExpr(self.vc, bits & 31, exp),0,finalsize-1)

        bits_size=self.getBitSizeFromExpr(bits)
        bits=self.simplify(self.uremExpr(bits,self.constExpr(32, bits_size)))
        if self.getKind(bits) == self._BVCONST:
            tmp=self.UConstFromExpr(bits)
            return self.extractExpr(self.CVC.vc_bvLeftShiftExpr(self.vc, tmp, exp),0,finalsize-1)

        for count in range(finalsize, -1, -1):
            if count != finalsize:
                ifpart = self.eqExpr(bits, self.constExpr(count, self.getBitSizeFromExpr(bits)))
                thenpart = self.extractExpr(self.CVC.vc_bvLeftShiftExpr(self.vc, count, exp), 0, finalsize-1)
                ite = self.iteExpr(ifpart, thenpart, elsepart)
                elsepart = ite
            else:
                elsepart = self.constExpr(0, finalsize)

        return ite | self.get_error()

    #the <bits> here might be an expression or a constant amount
    def rightArithmeticShiftExpr(self, exp, bits, finalsize=None):
        if not finalsize:
            finalsize=self.getBitSizeFromExpr(exp)

        if bits < 0x100:
            bits_size=32
            bits=self.constExpr(bits & 31, bits_size)
        else:
            bits_size=self.getBitSizeFromExpr(bits)
            bits=self.simplify(self.andExpr(bits,self.constExpr(31, bits_size)))

        signbit=self.extractExpr(exp, finalsize-1, finalsize-1)
        for count in range(finalsize, -1, -1):
            if count != finalsize:
                ifpart = self.eqExpr(bits, self.constExpr(count, self.getBitSizeFromExpr(bits)))
                if count:
                    #count=[1:31]
                    tmp2 = self.extractExpr(exp, count, finalsize-1)
                    tmp1 = signbit
                    for x in range(0, count-1):
                        tmp1 = self.concatExpr(tmp1, signbit)
                    thenpart = self.concatExpr(tmp1, tmp2)
                else:
                    #count=0
                    thenpart = exp
                ite = self.iteExpr(ifpart, thenpart, elsepart)
                elsepart = ite
            else:
                #count=32
                elsepart = signbit
                for x in range(0, finalsize-1):
                    elsepart = self.concatExpr(elsepart, signbit)

        return ite | self.get_error()

    #the <bits> here might be an expression or a constant amount
    def rightRotateExpr(self, exp, bits):
        finalsize = self.getBitSizeFromExpr(exp)
        if bits < 0x100:
            #this is a constant value
            bits=bits%finalsize
            if not bits:
                return exp

            return self.concatExpr(self.extractExpr(exp,0,bits-1),self.extractExpr(exp,bits,finalsize-1))

        bits_size=self.getBitSizeFromExpr(bits)
        bits=self.simplify(self.andExpr(bits,self.constExpr(31, bits_size)))
        if self.getKind(bits) == self._BVCONST:
            tmp=self.UConstFromExpr(bits)
            return self.rightRotateExpr(exp, tmp)

        for x in range(finalsize,-1,-1):
            if x != finalsize:
                ifpart=self.eqExpr(bits, self.constExpr(x, bits_size))
                if x == 0:
                    thenpart=exp
                else:
                    thenpart=self.concatExpr(self.extractExpr(exp,0,x-1),self.extractExpr(exp,x,finalsize-1))
                ite = self.iteExpr(ifpart, thenpart, elsepart)
                elsepart = ite
            else:
                elsepart = self.constExpr(0, finalsize)

        return ite | self.get_error()

    #the <bits> here might be an expression or a constant amount
    def rightShiftExpr(self, exp, bits, finalsize=None):
        #this code was copied almost verbatim from the c_interface file
        if not finalsize:
            finalsize=self.getBitSizeFromExpr(exp)

        if bits < 0x100:
            #this is a constant value, use the static version
            return self.extractExpr(self.CVC.vc_bvRightShiftExpr(self.vc, bits & 31, exp),0,finalsize-1)

        bits_size=self.getBitSizeFromExpr(bits)
        bits=self.simplify(self.andExpr(bits,self.constExpr(31, bits_size)))
        if self.getKind(bits) == self._BVCONST:
            tmp=self.UConstFromExpr(bits)
            return self.extractExpr(self.CVC.vc_bvRightShiftExpr(self.vc, tmp, exp),0,finalsize-1)

        for count in range(finalsize, -1, -1):
            if count != finalsize:
                ifpart = self.eqExpr(bits, self.constExpr(count, self.getBitSizeFromExpr(bits)))
                thenpart = self.CVC.vc_bvRightShiftExpr(self.vc, count, exp)
                ite = self.iteExpr(ifpart, thenpart, elsepart)
                elsepart = ite
            else:
                elsepart = self.constExpr(0, finalsize)

        return ite | self.get_error()

    def notExpr(self, exp):
        return self.CVC.vc_bvNotExpr(self.vc, exp) | self.get_error()

    def andExpr(self, exp1, exp2):
        return self.CVC.vc_bvAndExpr(self.vc, exp1, exp2) | self.get_error()

    def orExpr(self, exp1, exp2):
        return self.CVC.vc_bvOrExpr(self.vc, exp1, exp2) | self.get_error()

    def xorExpr(self, exp1, exp2):
        return self.CVC.vc_bvXorExpr(self.vc, exp1, exp2) | self.get_error()

    def negExpr(self, exp):
        return self.CVC.vc_bvUMinusExpr(self.vc, exp) | self.get_error()

    def addExpr(self, exp1, exp2, bits=None):
        if not bits: bits=self.getBitSizeFromExpr(exp1)
        return self.CVC.vc_bvPlusExpr(self.vc, bits, exp1, exp2) | self.get_error()

    def subExpr(self, exp1, exp2, bits=None):
        if not bits: bits=self.getBitSizeFromExpr(exp1)
        return self.CVC.vc_bvMinusExpr(self.vc, bits, exp1, exp2) | self.get_error()

    def umulExpr(self, exp1, exp2, bits=None):
        if not bits: bits=self.getBitSizeFromExpr(exp1)*2
        return self.CVC.vc_bvMultExpr(self.vc, bits, self.zeroExtendExpr(exp1, bits), self.zeroExtendExpr(exp2, bits)) | self.get_error()

    def udivExpr(self, exp1, exp2):
        return self.CVC.vc_bvUDivExpr(self.vc, exp1, self.zeroExtendExpr(exp2, self.getBitSizeFromExpr(exp1))) | self.get_error()

    def uremExpr(self, exp1, exp2):
        """unsigned remanent (modulo)"""
        return self.CVC.vc_bvURemExpr(self.vc, exp1, self.zeroExtendExpr(exp2, self.getBitSizeFromExpr(exp1))) | self.get_error()

    def sdivExpr(self, exp1, exp2):
        return self.CVC.vc_bvSDivExpr(self.vc, exp1, self.signExtendExpr(exp2, self.getBitSizeFromExpr(exp1))) | self.get_error()

    def sremExpr(self, exp1, exp2):
        return self.CVC.vc_bvSRemExpr(self.vc, exp1, self.signExtendExpr(exp2, self.getBitSizeFromExpr(exp1))) | self.get_error()

    def smodExpr(self, exp1, exp2):
        return self.CVC.vc_bvSModExpr(self.vc, exp1, self.signExtendExpr(exp2, self.getBitSizeFromExpr(exp1))) | self.get_error()

    def smulExpr(self, exp1, exp2, bits=None):
        if not bits: bits=self.getBitSizeFromExpr(exp1)*2
        return self.CVC.vc_bvMultExpr(self.vc, bits, self.signExtendExpr(exp1, bits), self.signExtendExpr(exp2, bits)) | self.get_error()

    def assignExpr(self, exp1, exp2, bits=None, endpos=0, pos=0, endbits=None):
        """
        Assign <bits> bits starting on position <pos> of exp2 to exp1 on position <endpos>
        The final expression is <endbits> bits long.
        NOTE: This function doesnt check brainfuckiness from the user, so if you assign 33bits to a 32bits BV it's up to you to fix your logic.
        NOTE2: position 0 here is the LEAST SIGNIFICANT BIT
        """

        exp1_size=self.getBitSizeFromExpr(exp1)
        exp2_size=self.getBitSizeFromExpr(exp2)
        if not endbits: endbits=exp1_size
        if not bits: bits=exp2_size

        if bits != exp2_size:
            tmp1=self.extractExpr(exp2, pos, pos+bits-1)
        else:
            tmp1=exp2
        if endpos != 0:
            tmp2=self.extractExpr(exp1, 0, endpos-1)
        else:
            tmp2=False
        if endpos+bits < endbits:
            tmp3=self.extractExpr(exp1, endpos+bits, endbits-1)
        else:
            tmp3=False

        if tmp3:
            final=self.concatExpr(tmp3, tmp1)
            if tmp1 != exp2:  #never delete original expressions, the caller should take care of that if needed
                self.deleteExpr(tmp1)
            self.deleteExpr(tmp3)
        else:
            final=tmp1
        if tmp2:
            tmp4=final
            final=self.concatExpr(tmp4, tmp2)
            self.deleteExpr(tmp2)
            self.deleteExpr(tmp4)
        return final

    def dumpExpr(self, exp, recursive=False, calchash=False):
        """
        Dumps all needed info for reconstructing an expression in a new solver instance.
        
        Worst part was to handle the skolemization. http://en.wikipedia.org/wiki/Skolem_normal_form
        
        If calchash == True: it calculates a CRC32 of the dump and store it in self.crc
        
        recursive is an argument used internally.
        
        Returns a 1,2 or 3-tuple depending of the expression:
        -Kind of expression (this is always returned)
        -Data: this is an opaque structure that loadExpr knows how to handle (if needed)
        -Childs: following the same format (if needed)
        """
        
        if not recursive:
            self.skolemExistsIdxs={}
            self.skolemExistsCrcs={}
            self.skolemExistsCounter=0
            self.variables={}
            self.crc=0
        
        kind = self.getKind(exp)
        if calchash:
            self.crc=crc32("%x"%kind, self.crc)
        dump=[kind]
        processChildren=False
        skolemExists=None
        
        #EXISTS/FORALL/LAMBDA
        if self.isClosure(exp):
            boundvars=[]
            for x in xrange(0, self.getNumVars(exp)):
                var=self.getVar(exp, x)
                boundvars.append((self.getName(var), self.getUid(var), self.dumpExpr(self.getType(var), True, calchash=calchash)))
                if calchash:
                    self.crc=crc32(boundvars[-1][0], self.crc)
                    self.crc=crc32("%x"%x, self.crc) #Uid might be unique for a given solver instance, var position is not.
            dump.append(tuple(boundvars))
            dump.append(self.dumpExpr(self.getBody(exp), True, calchash=calchash))
        elif kind == self._APPLY:
            data=[]
            fexp=self.getFunction(exp)
            for x in xrange(0, self.getArity(fexp)):
                child = self.getChild(fexp, x)
                if self.getKind(child) != self._RATIONAL_EXPR:
                    raise Exception, "Dont know how to dump this APPLY expression"
                data.append(self.getInt(child))
                if calchash:
                    self.crc=crc32("%x"%(data[-1] % (1<<32)), self.crc)
            realkind=self.getKind(fexp)
            if calchash:
                self.crc=crc32("%x"%realkind, self.crc)
            dump[0]=realkind
            dump.append(tuple(data))
            processChildren=True
        elif kind == self._RATIONAL_EXPR:
            dump.append( self.getInt(exp) )
            if calchash:
                self.crc=crc32("%x"%dump[-1], self.crc)
        elif kind == self._BVCONST:
            dump.append( (self.UConstFromExpr(exp), self.getBitSizeFromExpr(exp)) )
            if calchash:
                self.crc=crc32("%x"%(dump[-1][0] % (1<<dump[-1][1])), self.crc)
                self.crc=crc32("%x"%dump[-1][1], self.crc)
        elif kind == self._UCONST:
            name = self.getName(exp)
            dump.append( (name, self.dumpExpr(self.getType(exp), True, calchash=calchash)) )
            if calchash:
                self.crc=crc32(dump[-1][0], self.crc)
            self.variables[name]=exp
        elif kind == self._BOUND_VAR:
            dump.append( (self.getName(exp), self.getUid(exp), self.dumpExpr(self.getType(exp), True, calchash=calchash)) )
            if calchash:
                self.crc=crc32(dump[-1][0], self.crc)
        elif kind == self._SKOLEM_VAR:
            #un-skolemize SKOLEM_VARs
            exists=self.getExistential(exp)
            idx=self.getIndex(exists)
            if idx not in self.skolemExistsIdxs.keys():
                self.skolemExistsIdxs[idx]=self.skolemExistsCounter #recursive safetyness trick!
                self.skolemExistsCounter+=1
                skolemExists = self.dumpExpr(exists, True, calchash=calchash)
                
                if calchash:
                    self.skolemExistsCrcs[idx]=self.crc
            dump.append( (self.getBoundIndex(exp), self.skolemExistsIdxs[idx]) )
            if calchash:
                self.crc=crc32("%x"%dump[-1][0], self.crc)
                self.crc=crc32("%x"%(self.skolemExistsCrcs[idx] % (1<<32)), self.crc)
        else:
            processChildren=True
        
        if processChildren:
            childs=[]
            for x in xrange(0, self.getArity(exp)):
                child=self.getChild(exp, x)
                childs.append( self.dumpExpr(child, True, calchash=calchash) )
            
            if childs:
                dump.append(tuple(childs))
        
        if self.DEBUG:
            dump[0]=self.getKindString(dump[0])
        
        if skolemExists:
            return (tuple(skolemExists), self.skolemExistsIdxs[idx], tuple(dump))
        else:
            return tuple(dump)
    
    def loadExpr(self, dump, recursive=False, varsdict=None):
        """
        Loads an expression to the current solver's context. It takes the output from dumpExpr.
        
        varsdict is a dictionary of assignments for variables, useful for merging expressions.
        ex: EAX=2+2
            ECX=EAX+EBX => ECX=2+2+EBX
        
        """
        
        kindMap = { self._EXISTS:self.existsExpr,\
                    self._FORALL:self.forallExpr,\
                    self._LAMBDA:self.lambdaExpr,\
                    self._EQ:self.eqExpr,\
                    self._NEQ:self.neExpr,\
                    self._TRUE_EXPR:self.trueExpr,\
                    self._FALSE_EXPR:self.falseExpr,\
                    self._BVUDIV:self.udivExpr,\
                    self._BVSDIV:self.sdivExpr,\
                    self._NOT:self.boolNotExpr,\
                    self._AND:self.boolAndExpr,\
                    self._OR:self.boolOrExpr,\
                    self._IFF:self.iffExpr,\
                    self._IMPLIES:self.impliesExpr,\
                    self._CONCAT:self.concatExpr,\
                    self._BVAND:self.andExpr,\
                    self._BVOR:self.orExpr,\
                    self._BVXOR:self.xorExpr,\
                    self._BVNEG:self.notExpr,\
                    self._BVUMINUS:self.negExpr,\
                    self._BVUREM:self.uremExpr,\
                    self._BVSREM:self.sremExpr,\
                    self._BVSMOD:self.smodExpr,\
                    self._BVLT:self.ltExpr,\
                    self._BVLE:self.leExpr,\
                    self._BVGT:self.gtExpr,\
                    self._BVGE:self.geExpr,\
                    self._BVSLT:self.sltExpr,\
                    self._BVSLE:self.sleExpr,\
                    self._BVSGT:self.sgtExpr,\
                    self._BVSGE:self.sgeExpr
                    }

        if not recursive:
            self.state={ "vars":{}, "boundVars":{}, "skolemExists":{}, "skolemVars":{} }
            if varsdict:
                for k,v in varsdict.iteritems():
                    self.state["vars"][k]=v
            
        if len(dump) == 3 and isinstance(dump[0], tuple) and isinstance(dump[1], int):
            self.state["skolemExists"][dump[1]]=self.loadExpr(dump[0], True)
            dump=dump[2]
        
        kind=dump[0]

        if kind == self._BITVECTOR:
            bvsize = dump[1][0][1]
            if not hasattr(self, "bv%dbits"%bvsize):
                setattr(self, "bv%dbits"%bvsize, self.bvType(bvsize))
            return getattr(self, "bv%dbits"%bvsize)
        
        elif kind == self._BOOLEAN:
            return self.booltype
        
        elif kind == self._UCONST:
            if dump[1][0] not in self.state["vars"].keys():
                tmp=self.lookupVar(dump[1][0])
                if not tmp:
                    vartype = self.loadExpr(dump[1][1], True)
                    tmp=self.varExpr(dump[1][0], vartype)
                else:
                    tmp=tmp[0]
                self.state["vars"][dump[1][0]]=tmp
            return self.state["vars"][dump[1][0]]
        
        elif kind == self._BVCONST:
            return self.constExpr(dump[1][0], dump[1][1])
        
        elif kind == self._BOUND_VAR:
            tmpkey=dump[1][0] + dump[1][1]
            if tmpkey not in self.state["boundVars"].keys():
                vartype = self.loadExpr(dump[1][2], True)
                self.state["boundVars"][tmpkey]=self.boundVarExpr(dump[1][0], dump[1][1], vartype)
            return self.state["boundVars"][tmpkey]
        
        elif kind == self._SKOLEM_VAR:
            boundIdx=dump[1][0]
            existsIdx=dump[1][1]
            skey=(boundIdx << 16) + existsIdx
            if skey not in self.state["skolemVars"].keys():
                exists=self.state["skolemExists"][existsIdx]
                boundVars=[]
                skolemVars=[]
                
                #re-skolemization
                for x in xrange(0, self.getNumVars(exists)):
                    boundVars.append(self.getVar(exists, x))
                    svar=self.skolemizeVar(exists, x)
                    skolemVars.append(svar)
                    self.state["skolemVars"][(x << 16) + existsIdx]=svar
                skolemized=self.skolemize(exists, boundVars, skolemVars)
                self.assertFormula(skolemized)
            
            return self.state["skolemVars"][skey]
        
        elif kind in (self._EXISTS, self._FORALL, self._LAMBDA):
            bvars=[]
            for bvarDump in dump[1]:
                bvars.append(self.loadExpr( (self._BOUND_VAR, bvarDump), True))
            
            func = kindMap[kind]
            return func(bvars, self.loadExpr(dump[2], True))
        
        elif kind == self._EXTRACT:
            return self.extractExpr(self.loadExpr(dump[2][0], True), dump[1][1], dump[1][0])
        
        elif kind == self._BOOLEXTRACT:
            return self.boolExtractExpr(self.loadExpr(dump[2][0], True), dump[1][0])
        
        elif kind == self._SX:
            return self.signExtendExpr(self.loadExpr(dump[2][0], True), dump[1][0])
        
        elif kind == self._BVZEROEXTEND:
            return self.zeroExtendExpr(self.loadExpr(dump[2][0], True), dump[1][0])
            
        elif kind == self._BVPLUS:
            tmp = self.addExpr(self.loadExpr(dump[2][0], True), self.loadExpr(dump[2][1], True), dump[1][0])
            c=2
            while c < len(dump[2]):
                tmp = self.addExpr(tmp, self.loadExpr(dump[2][c], True), dump[1][0])
                c+=1
            return tmp
        
        elif kind == self._BVSUB:
            if len(dump) == 3:
                return self.subExpr(self.loadExpr(dump[2][0], True), self.loadExpr(dump[2][1], True), dump[1][0])
            else:
                return self.subExpr(self.loadExpr(dump[1][0], True), self.loadExpr(dump[1][1], True))
        
        elif kind == self._BVMULT:
            exp1=self.loadExpr(dump[2][0], True)
            exp2=self.loadExpr(dump[2][1], True)
            bits=dump[1][0]
            return self.CVC.vc_bvMultExpr(self.vc, bits, exp1, exp2) | self.get_error()
        
        elif kind == self._DISTINCT:
            children=[]
            for child in dump[1]:
                children.append(self.loadExpr(child, True))
            return self.distinctExpr(children)
        
        elif kind == self._CONST_WIDTH_LEFTSHIFT:
            return self.leftShiftExpr(self.loadExpr(dump[2][0], True), dump[1][0])
        
        elif kind == self._RIGHTSHIFT:
            return self.rightShiftExpr(self.loadExpr(dump[2][0], True), dump[1][0])
        
        elif kind == self._ITE:
            return self.iteExpr(self.loadExpr(dump[1][0], True), self.loadExpr(dump[1][1], True), self.loadExpr(dump[1][2], True))
        
        else:
            func=kindMap[kind]
            
            #handle functions that take 1..n arguments
            children=[]
            if len(dump) > 1:
                for child in dump[1]:
                    children.append(self.loadExpr(child, True))
            
            args=[]
            if children: args.insert(0, children.pop()) #first arg
            if children: args.insert(0, children.pop()) #second arg
            tmp = func(*args)
            while len(children):
                args=[children.pop()]
                args.append(tmp)
                tmp=func(*args)
            
            return tmp

    def getVarDependency(self, exp, return_name=False):
        """
        return the list a variables involved in an expression.
        ex: a const value expression would return None
            EAX+EBX+1*EAX would return [EAX,EBX]
        
        return_name decides if the name of the variable or the actual var expression is returned.
        """
        
        dump = self.dumpExpr(exp)
        if return_name:
            return self.variables.keys()
        else:
            return self.variables.values()
    
    def hashExpr(self, exp):
        """
        return a 32bits number that identifies an expression (regardless the current context/solver instance).
        
        """
        
        self.dumpExpr(exp, calchash=True)
        return self.crc % (1<<32)
    
    def mergeExpr(self, exp, varsdict):
        dump=self.dumpExpr(exp)
        return self.loadExpr(dump, varsdict=varsdict)

    def concreteModelGenerator(self, exp):
        """
        This function returns an iterator that can be used to return all possible concrete models for a given expression.
        """

        self.push()
        kind=self.getKind(self.getType(exp))
        if kind == self._BOOLEAN:
            while self.checkSat(exp):
                r=self.getConcreteModel()
                self.returnFromCheck()
                
                tmp = r[:]
                asserts=tmp.pop()
                
                for x in tmp:
                    asserts=self.boolAndExpr(asserts, x)
                
                self.assertFormula(self.boolNotExpr(asserts))
                yield r
        
        self.pop()
        return

    #Array functions
    def readExpr(self, array, index):
        return self.CVC.vc_readExpr(self.vc, array, index) | self.get_error()
        
    def writeExpr(self, array, index, value):
        return self.CVC.vc_writeExpr(self.vc, array, index, value) | self.get_error()
    
    def createMemoryArray(self, array_name):
        """
        @param array_name: A unique name for the array
        @type array_name: String

        @rtype: Expr
        @returns: An Expr type representing a CVC3 array
        """

        return self.CVC.vc_bvCreateMemoryArray(self.vc,
            create_string_buffer(array_name))

    def readMemoryArray(self, array, byte_index, num_of_bytes):
        """
        @param array: The array to read from
        @type array: Expr

        @param byte_index: The index to start reading at
        @type byte_index: Expr

        @param num_of_bytes: The number of bytes to read
        @type num_of_bytes: Int

        @return: An expression representing a read from the array
        @rtype: Expr
        """

        return self.CVC.vc_bvReadMemoryArray(self.vc, array, byte_index,
            num_of_bytes) 

    def writeToMemoryArray(self, array, byte_index, element,
            num_of_bytes):
        """
        @param array: The array to write to 
        @type array: Expr

        @param byte_index: The index to start writing at
        @type byte_index: Expr

        @param element: An expression representing the byte value to 
            write. This bitvector must be 8 bits in size.
        @type element: Expr

        @param num_of_bytes: The number of bytes to write
        @type num_of_bytes: Int

        @return: An expression representing a write to the array
        @rtype: Expr
        """

        return self.CVC.vc_bvWriteToMemoryArray(self.vc, array,
            byte_index, element, num_of_bytes)

