"""
Here we support Expression and Type classes which work as wrappers against the PrettySolver class (which is itself a wrapper around Solver).

Doing so, we can support native python operators over Solver Expressions:
- All comparision expressions are supported (doing a queryFormula over the comparision if we are in a boolean context)
- Conversion to boolean only returns True if it's a VALID answer.
- All arithmetical and logical operations are supported (if you're working with BOOLEAN expressions it uses the appropiate boolean operations)
- It allows you to interact with non-expression operands by casting them to Expression instances where possible:
  - int/longs to constExpr
  - strings to varDef
  - tuples to loadExpr
  - boolean to trueExpr/falseExpr
- It imports expressions from other solver instances automatically
- len(expr) returns the number of bits on a BV (it returns None if BOOLEAN)
- allows slice getting/setting: expr[0:16] returns the lower 16bits of a BV
- cast to int/long if the expression can be evaluated to a constant
- some handy methods were added:
  - vars() return all variable expressions that are involved in the current expression
  - varsnames() same but return the names, no the expressions
  - dump() same as dumpExpr(self)
  - load() set the current expression with a dump
  - other stuff...
"""

from solver_cvc3 import Solver
global psolvers, default_psolver
psolvers={}
default_psolver = None

import math

class Expression():
    def __init__(self, expr=None, psolver=None, addr=None, signed=False, lang=0, boolean=False, bits=32):
        """
        Possible languages for input/output:
                       0 - PRESENTATION (CVC3 format)
                       1 - SMTLIB
                       2 - LISP
                       3 - AST
                       4 - SIMPLIFY
                       5 - TPTP
        """
        
        if psolver == None:
            #use the default psolver
            global psolvers, default_psolver
            if default_psolver == None:
                #init a new Pretty Solver
                psolver = PrettySolver()
                psolvers[id(psolver)]=psolver
                default_psolver = id(psolver)
            else:
                psolver = psolvers[default_psolver]
                
        self.psolver = psolver
        self.addr = addr
        self.lang = lang
        self.hash = None
        self.signed = signed #by default we use unsigned bitvectors
        
        if expr != None:
            self.addr = self.convertToExpr(expr, boolean, bits).addr
    
    def __getstate__(self):
        """
        Pretty Solvers should not be copied, deepcopied or pickled, so we maintain a global list of already initialized psolvers.
        """
        
        global psolvers
        psolvers[id(self.psolver)]=self.psolver
        return (id(self.psolver), self.addr, self.lang, self.hash, self.signed)
    
    def __setstate__(self, dump):
        global psolvers
        (tmp, self.addr, self.lang, self.hash, self.signed) = dump
        self.psolver=psolvers[tmp]
    
    def __str__(self):
        return self.psolver.exprString(self)
    
    def __repr__(self):
        return "<Expression '%s'>"%self.psolver.exprString(self)
    
    def __hash__(self):
        if self.hash == None:
            self.hash=self.psolver.hashExpr(self)
        return self.hash
    
    def convertToExpr(self, b, boolean=False, bits=32):
        if isinstance(b, Expression):
            if self.psolver.solver.vc != b.psolver.solver.vc:
                b=self.psolver.importExpr(b)
            return b
        
        if isinstance(b, tuple):
            return self.psolver.loadExpr(b)
        
        if isinstance(b, bool) or (isinstance(b, str) and (b.lower() == "true" or b.lower() == "false")):
            if isinstance(b, str):
                if b.lower() == "true": b=True
                else: b=False
            
            if b:
                return self.psolver.trueExpr()
            else:
                return self.psolver.falseExpr()
            
        if isinstance(b, str):
            tmp=self.psolver.lookupVar(b)
            if tmp:
                return tmp[0]
            
            #only allow [A-Z0-9_-] for variable names
            if b.replace("_","").replace("-","").isalnum():
                if (self.addr and self.isBoolean()) or boolean == True:
                    return self.psolver.varExpr(b, self.psolver.booltype)
                else:
                    if bits in [8,16,32,64]:
                        return self.psolver.varExpr(b, getattr(self.psolver, "bv%dbits"%bits), signed=self.signed) #pre-initialized BV Types
                    else:
                        return self.psolver.varExpr(b, self.psolver.bvType(bits), signed=self.signed) #custom BV Type
            else:
                if self.lang == 0: #PRESENTATION lang
                    b = "PRINT " + b + ";"
                return self.psolver.exprFromStringAndLang(b, self.lang, self.signed) #Try to interpret it as a complete formula
        
        if isinstance(b, int) or isinstance(b, long):
            if self.addr:
                return self.psolver.constExpr(b, self.psolver.getBitSizeFromExpr(self), self.signed) #here we're making two compatible expressions
            else:
                return self.psolver.constExpr(b, bits, self.signed) #here we're initializing a new expression
        
        raise Exception, "Dont know how to convert this to an Expression"
    
    def matchSizes(self, b, signedop, unsignedop):
        """
        match bitvector sizes and execute a signed/unsigned operation following this rules:
        - if there's a size conversion, it uses the signedness of the unconverted expression.
        - if there's no conversion and there's a difference in signedness it's unsigned.
        """
        
        lenL=len(self)
        lenR=len(b)
        if lenL > lenR:
            left = self
            right = b.clone()
            right.extend(lenL)
            signed = self.signed
        elif lenR > lenL:
            left = self.clone()
            left.extend(lenR)
            right = b
            signed = b.signed
        else:
            left = self
            right = b
            signed = left.signed and right.signed
        
        if signed:
            tmp = signedop(left, right)
        else:
            tmp = unsignedop(left, right)
        
        tmp.signed = signed
        return tmp
        
    def __eq__(self, b):
        if b == None: return False
        b=self.convertToExpr(b)
        if self.isBoolean():
            exp = self.psolver.iffExpr(self, b)
        else:
            exp = self.matchSizes(b, self.psolver.eqExpr, self.psolver.eqExpr)
        return exp
    
    def __ne__(self, b):
        if b == None: return True
        return self.psolver.boolNotExpr(self.__eq__(b))
    
    def __lt__(self, b):
        b=self.convertToExpr(b)
        return self.matchSizes(b, self.psolver.sltExpr, self.psolver.ltExpr)
    
    def __le__(self, b):
        b=self.convertToExpr(b)
        return self.matchSizes(b, self.psolver.sleExpr, self.psolver.leExpr)
    
    def __gt__(self, b):
        b=self.convertToExpr(b)
        return self.matchSizes(b, self.psolver.sgtExpr, self.psolver.gtExpr)
    
    def __ge__(self, b):
        b=self.convertToExpr(b)
        return self.matchSizes(b, self.psolver.sgeExpr, self.psolver.geExpr)
    
    def __nonzero__(self):
        """
        We use VALID queries here (instead of SAT) because python uses shortcircuit boolean checks on "if" statements,
        so it checks the conditions one by one and not all together.
        
        for example, in a SAT query, this:
        if a < 10 and a > 20: print "BLA"
        would actually return SAT, because it first check if a < 10 is SAT and then a > 20.
        
        if we use VALID queries it doesnt matter the order, because answers are universally valid. 
        
        If you still need to use SAT queries, you can do:
        if ((a < 100) & (a == k * 2)).isSAT(): print "BLA"
        
        Note the use of & instead of python's keyword "and", 
        the & operator is polymorphic and can handle both, BITVECTOR and BOOLEAN expressions.
        """
        
        if self.isBoolean():
            return self.isVALID()
        else:
            return (self != 0).isVALID()
    
    def __len__(self):
        return self.psolver.getBitSizeFromExpr(self)
    
    def __getitem__(self, key):
        if self.isBoolean():
            raise IndexError #to cut loops before iterating
        
        if isinstance(key, Expression):
            key=key.__int__()
            if key == None: raise TypeError
        
        if isinstance(key, int) or isinstance(key, long):
            stop = key
            start = key
        else:
            start=key.start
            stop=key.stop-1
        if start == None: start=0
        if stop == 0x7FFFFFFE: stop = self.__len__()-1
        if start < 0 or stop < 0:
            bits=self.psolver.getBitSizeFromExpr(self)
            if start < 0: start = bits + start
            if stop < 0: stop = bits + stop
        
        return self.psolver.extractExpr(self, start, stop)
    
    def __setitem__(self, key, value):
        if self.isBoolean():
            raise IndexError #to cut loops before iterating
        
        if isinstance(key, Expression):
            key=key.__int__()
            if key == None: raise TypeError
        
        value=self.convertToExpr(value)
        
        if isinstance(key, int) or isinstance(key, long):
            stop = key
            start = key
        else:
            start=key.start
            stop=key.stop-1
        if start == None: start=0
        if stop == 0x7FFFFFFE: stop = self.__len__()-1
        if start < 0 or stop < 0:
            bits=self.psolver.getBitSizeFromExpr(self)
            if start < 0: start = bits + start
            if stop < 0: stop = bits + stop

        size=stop-start+1
        if len(value) > size:
            chunk=self.psolver.extractExpr(value, 0, size-1)
        elif len(value) < size:
            chunk=value.clone()
            chunk.extend(size)
        else:
            chunk=value
            
        self.addr=self.psolver.assignExpr(self, chunk, size, start).addr
        self.hash=None
    
    def __add__(self, b):
        b=self.convertToExpr(b)
        return self.matchSizes(b, self.psolver.addExpr, self.psolver.addExpr)
    
    def __sub__(self, b):
        b=self.convertToExpr(b)
        return self.matchSizes(b, self.psolver.subExpr, self.psolver.subExpr)
    
    def __floordiv__(self, b):
        b=self.convertToExpr(b)
        return self.matchSizes(b, self.psolver.sdivExpr, self.psolver.udivExpr)
    
    def __div__(self, b):
        b=self.convertToExpr(b)
        return self.matchSizes(b, self.psolver.sdivExpr, self.psolver.udivExpr)
    
    def __mod__(self, b):
        b=self.convertToExpr(b)
        return self.matchSizes(b, self.psolver.sremExpr, self.psolver.uremExpr)
    
    def __mul__(self, b):
        b=self.convertToExpr(b)
        return self.matchSizes(b, self.psolver.smulExpr, self.psolver.umulExpr)
    
    def __lshift__(self, b):
        if isinstance(b, int) or isinstance(b, long):
            return self.psolver.leftShiftExpr(self, b)
        b=self.convertToExpr(b)
        return self.psolver.leftShiftExpr(self, b)
    
    def __rlshift__(self, b):
        return self.__lshift__(b)
    
    def __rshift__(self, b):
        if isinstance(b, int) or isinstance(b, long):
            return self.psolver.rightShiftExpr(self, b)
        b=self.convertToExpr(b)
        return self.psolver.rightShiftExpr(self, b)
    
    def __rrshift__(self, b):
        return self.__rshift__(b)
    
    def __and__(self, b):
        b=self.convertToExpr(b)
        if self.isBoolean():
            return self.psolver.boolAndExpr(self, b)
        else:
            return self.matchSizes(b, self.psolver.andExpr, self.psolver.andExpr)
    
    def __xor__(self, b):
        b=self.convertToExpr(b)
        if self.isBoolean():
            return self.psolver.boolXorExpr(self, b)
        else:
            return self.matchSizes(b, self.psolver.xorExpr, self.psolver.xorExpr)
    
    def __or__(self, b):
        b=self.convertToExpr(b)
        if self.isBoolean():
            return self.psolver.boolOrExpr(self, b)
        else:
            return self.matchSizes(b, self.psolver.orExpr, self.psolver.orExpr)
    
    def __invert__(self):
        if self.isBoolean():
            return self.psolver.boolNotExpr(self)
        else:
            return self.psolver.notExpr(self)
    
    def __neg__(self):
        if self.isBoolean():
            raise Exception, "You can't negate a BOOLEAN expression"
        return self.psolver.negExpr(self)
    
    def __int__(self):
        tmp=self.psolver.simplify(self)
        tmp=self.psolver.UConstFromExpr(tmp)
        if tmp==None:
            raise ValueError, "The expression cannot be evaluated as a constant number"
        
        size = len(self)
        if self.signed and tmp >> (size-1):
            #this is a negative number
            return int("-%d"%(-tmp % (1 << size)))
        
        return tmp
    
    def __long__(self):
        return self.__int__()
    
    def vars(self):
        """
        return the variables found in this expression
        """
        return self.psolver.getVarDependency(self, False)
    
    def varsnames(self):
        """
        return the variable's names found in this expression
        """
        return self.psolver.getVarDependency(self, True)
    
    def isSkolem(self):
        return self.psolver.isSkolem(self)
    
    def isClosure(self):
        return self.psolver.isClosure(self)
    
    def existential(self):
        return self.psolver.getExistential(self)

    def kind(self):
        return self.psolver.getKind(self)
    
    def dump(self):
        return self.psolver.dumpExpr(self)
    
    def load(self, dump):
        #IN-PLACE!!

        #this hack allows us to avoid the creation of a new Expression instance
        self.addr = self.psolver.solver.loadExpr(dump[0])
        self.lang = dump[1]
        self.signed = dump[2]
        self.hash=None

    def simplify(self):
        #IN-PLACE!!
        
        #this hack allows us to avoid the creation of a new Expression instance
        self.addr = self.psolver.solver.simplify(self.addr)
        self.hash=None
    
    def extend(self, bits):
        """
        bits is the final size of the bitvector
        """
        #IN-PLACE!!
        
        if self.signed:
            self.signExtend(bits)
        else:
            self.zeroExtend(bits)
        
    def zeroExtend(self, bits):
        #IN-PLACE!!
        self.addr = self.psolver.solver.zeroExtendExpr(self.addr, bits)
        self.hash=None

    def signExtend(self, bits):
        #IN-PLACE!!
        self.addr = self.psolver.solver.signExtendExpr(self.addr, bits)
        self.hash=None

    def isConstant(self):
        try:
            self.__int__()
            return True
        except ValueError:
            return False
    
    def isBoolean(self):
        return self.psolver.getKind(self.psolver.getType(self)) == self.psolver.solver._BOOLEAN
    
    def merge(self, mergeDict):
        tmp=self.psolver.mergeExpr(self, mergeDict)
        return tmp
    
    def getCounterExample(self):
        if self.isBoolean() and self.psolver.checkSat(self):
            r=self.psolver.getCounterExample()
            self.psolver.returnFromCheck()
            return r
        else:
            return False
    
    def getConcreteModel(self):
        if self.isBoolean() and self.psolver.checkSat(self):
            r=self.psolver.getConcreteModel()
            self.psolver.returnFromCheck()
            return r
        else:
            return False
    
    def concreteModelGenerator(self):
        """
        This function returns an iterator that can be used to return all possible concrete models for a given expression.
        """
        
        for item in self.psolver.concreteModelGenerator(self):
            yield item
        
        return
    
    def isSAT(self):
        """
        Returns a boolean indicating if the expression is SAT or not, or None if the expression is not boolean.
        """
        if self.isBoolean():
            ret = self.psolver.checkSat(self)
            if ret:
                self.psolver.returnFromCheck()
            return ret
        return None
    
    def assertIt(self):
        self.psolver.assertFormula(self)
    
    def isVALID(self):
        """
        same as evaluating the Expression in a python "if" statement
        """
        
        res=self.psolver.queryFormula(self)
        if res == 1:
            return True
        elif res == 0:
            self.psolver.returnFromCheck()
            return False
        else:
            return None
    
    def clone(self):
        """
        returns a new Expression instance pointing to a new solver expression that is equal to the current one.
        
        Note that the new expression is NOT linked to the current one.
        """
        
        tmp = Expression(psolver=self.psolver)
        tmp.load(self.dump())
        
        return tmp
        
    def fromString(self, exprstring):
        #IN-PLACE!!
        if self.lang == 0:
            exprstring = "PRINT " + exprstring + ";"
        self.addr = self.psolver.exprFromStringAndLang(exprstring, self.lang).addr
        self.hash = None
    
    def boundaries(self):
        """
        Return the upper and lower boundaries of all variables involved in a boolean expression.
        
        """
        
        oldaddr = None
        if not self.isBoolean():
            #HACK!!
            #save the orig expression and simulate a boolean expression
            #this makes sense because the system might have assertions
            #that limit a variable, if not, the whole var range will be returned
            oldaddr = self.addr
            self.addr = self.psolver.eqExpr(self, self).addr
        
        variables={}
        for v in self.vars():
            boundaries=None
            if not v.isBoolean():
                #find lower and upper boundaries
                overupper = -1
                bvsize = len(v)
                
                for x in xrange(0, bvsize):
                    #check each bit if it can be 1
                    if not (self & (v[x] == 1)).isSAT(): #this bit cant be one, so we adjust the upper boundary
                        overupper ^= 1 << x
                
                overupper %= 1 << bvsize #transform to a positive number
                
                #find an overapproximation of the lower boundary
                for x in xrange(bvsize, -1, -1):
                    overlower = (1 << x) - 1
                    if not (self & (v <= overlower)).isSAT():
                        break
                
                #Now we do a binary search to find the real boundary, which is going to be between the calculated value and the next/prior power of two
                
                #upper boundary first
                valrange = overupper - (overupper >> 1)
                upper = overupper
                
                while not (self & (v == overupper)).isSAT():
                    upper = overupper - valrange//2
                    if not (self & (v > upper)).isSAT():
                        #lower half
                        overupper=upper
                    
                    valrange//=2
                
                
                #lower boundary
                valrange = overlower + 1
                lower = overlower
                
                while not (self & (v == overlower)).isSAT():
                    lower = overlower + int(math.ceil(valrange/2.0))
                    if not (self & (v < lower)).isSAT():
                        #upper half
                        overlower=lower
                    
                    valrange=int(math.ceil(valrange/2.0))
                
                boundaries = (lower, upper)
            
            variables[v]=boundaries
        
        
        #revert the hack for non boolean expressions
        if oldaddr:
            self.addr = oldaddr
        
        return variables

class Type():
    def __init__(self, psolver, addr=None):
        self.psolver = psolver
        self.addr = addr
        
        
class PrettySolver():
    def __init__(self, solver=None, debug=False):
        if not solver:
            self.solver = Solver()
        else:
            self.solver = solver
        self.initCommonTypes()
        
        self.solver.DEBUG = debug
        self.variables = {}
        
        #keep track of all Pretty Solvers
        global psolvers, default_psolver
        psolvers[id(self)]=self
        if default_psolver == None:
            default_psolver = id(self)
    
    def setDebug(self, debug):
        self.solver.DEBUG = debug
        
    def initCommonTypes(self):
        self.bv64bits=self.bvType(64)
        self.bv32bits=self.bvType(32)
        self.bv16bits=self.bvType(16)
        self.bv8bits=self.bvType(8)
        self.booltype=self.boolType()
        self.true=self.trueExpr()
        self.false=self.falseExpr()

    def createExpression(self, exprstring=None, addr=None, signed=False, lang=0):
        return Expression(exprstring, self, addr, signed, lang)
        
    def assertFormula(self, exp):
        self.solver.assertFormula(exp.addr)

    def queryFormula(self, exp):
        return self.solver.queryFormula(exp.addr)

    def checkUnsat(self, exp):
        return self.solver.checkUnsat(exp.addr)

    def checkSat(self, exp):
        return self.solver.checkSat(exp.addr)
    
    def checkContinue(self):
        return self.solver.checkContinue()

    def restart(self, exp):
        return self.solver.restart(exp.addr)

    def returnFromCheck(self):
        self.solver.returnFromCheck()

    def getCounterExample(self):
        ret=[]
        for e in self.solver.getCounterExample():
            ret.append(Expression(None, self, e))
        return ret

    def getConcreteModel(self):
        ret=[]
        for e in self.solver.getConcreteModel():
            ret.append(Expression(None, self, e))
        return ret

    def getUserAssumptions(self):
        ret=[]
        for e in self.solver.getUserAssumptions():
            ret.append(Expression(None, self, e))
        return ret

    def getInternalAssumptions(self):
        ret=[]
        for e in self.solver.getInternalAssumptions():
            ret.append(Expression(None, self, e))
        return ret

    def getAssumptions(self):
        ret=[]
        for e in self.solver.getAssumptions():
            ret.append(Expression(None, self, e))
        return ret

    def getAxioms(self, exp):
        ret=[]
        for e in self.solver.getAxioms(exp.addr):
            ret.append(Expression(None, self, e))
        return ret

    def getIndex(self, exp):
        return self.solver.getIndex(exp.addr)

    def getExistential(self, exp):
        return Expression(None, self, self.solver.getExistential(exp.addr))

    def getNumVars(self, exp):
        return self.solver.getNumVars(exp.addr)

    def getVar(self, exp, ind):
        return Expression(None, self, self.solver.getVar(exp.addr, ind))

    def getArity(self, exp):
        return self.solver.getArity(exp.addr)

    def getChild(self, exp, ind):
        return Expression(None, self, self.solver.getChild(exp.addr, ind))

    def getBody(self, exp):
        return Expression(None, self, self.solver.getBody(exp.addr))

    def getKind(self, exp):
        return self.solver.getKind(exp.addr)

    def getClosure(self):
        return Expression(None, self, self.solver.getClosure())

    def isClosure(self, exp):
        return self.solver.isClosure(exp.addr)

    def isSkolem(self, exp):
        return self.solver.isSkolem(exp.addr)

    def getBoundIndex(self, exp):
        return self.solver.getBoundIndex(exp.addr)
    
    def getFunction(self, exp):
        return Expression(None, self, self.solver.getFunction(exp.addr))
        
    def incomplete(self):
        return self.solver.incomplete()

    def getProof(self):
        return Expression(None, self, self.solver.getProof())

    #Context methods
    def stackLevel(self):
        return self.solver.stackLevel()

    def push(self):
        return self.solver.push()

    def pop(self):
        return self.solver.pop()

    def popto(self, level):
        return self.solver.popto(level)

    #Misc functions
    def deleteExpr(self,exp):
        self.solver.deleteExpr(exp.addr)

    def importExpr(self, exp):
        return Expression(None, self, self.solver.importExpr(exp.addr), exp.signed)

    #returns a simplified Expr
    def simplify(self, exp):
        return Expression(None, self, self.solver.simplify(exp.addr), exp.signed)

    def parseFile(self, filename):
        self.solver.parseFile(filename)

    #returns a new Bit-Vector Type of <bits> bits
    def bvType(self, bits=32):
        return Type(self, self.solver.bvType(bits))

    def boolType(self):
        return Type(self, self.solver.boolType())

    def boundVarExpr(self, name, uid, vartype=None, signed=False):
        if vartype: vartype = vartype.addr
        return Expression(None, self, self.solver.boundVarExpr(name, uid, vartype), signed)
    
    #returns a variable Expr
    def varExpr(self, name, vartype=None, signed=False):
        if vartype and isinstance(vartype, Type):
            vartype = vartype.addr
        tmp=Expression(None, self, self.solver.varExpr(name, vartype), signed)
        self.variables[name]=(tmp, vartype)
        return tmp

    #returns a variable Expr initialized with a given Expr
    def varDefExpr(self, name, definition, vartype=None, signed=False):
        if vartype and isinstance(vartype, Type):
            vartype = vartype.addr
        tmp = Expression(None, self, self.solver.varDefExpr(name, definition.addr, vartype), signed)
        self.variables[name]=(tmp, vartype)
        return tmp

    def createTypeFromString(self, typename):
        return Type(self, self.solver.createTypeFromString(typename))
    
    def lookupVar(self, name):
        if self.variables.has_key(name): #return cached variables only, this way we maintain signedness
            vartype = self.variables[name][1]
            if not isinstance(vartype, Type):
                vartype = self.solver.bv32bits
            
            return (self.variables[name][0], Type(self, vartype))
        
        return False

    #Utils
    def compareExpr(self, exp1, exp2):
        return self.solver.compareExpr(exp1.addr, exp2.addr)

    def exprFromString(self, stri, signed=False):
        return Expression(None, self, self.solver.exprFromString(stri), signed)

    def exprFromStringAndLang(self, stri, lang, signed=False):
        """
        This receives a list of commands, not formulas.
        """
        
        return Expression(None, self, self.solver.exprFromStringAndLang(stri, lang), signed)

    def exprString(self, exp, lang=None):
        if lang == None: lang = exp.lang
        ret=self.solver.exprString(exp.addr, lang)
        
        if not lang: #convert binary numbers to hex
            ret = ret.split("0bin")
            out=""
            
            out+=ret.pop(0)
            
            for b in ret:
                intbuf=""
                
                for idx in xrange(0, len(b)):
                    if b[idx] != "1" and b[idx] != "0":
                        break
                    else:
                        intbuf+=b[idx]
                
                if (len(intbuf) % 4) == 0:
                    out+="0hex"
                    out+="%X"%int(intbuf,2)
                    out+=b[len(intbuf):]
                else:
                    out+="0bin"
                    out+=b
            
            ret = out
        
        return ret

    def getType(self, exp):
        return Type(self, self.solver.getType(exp.addr))

    def getName(self, exp):
        return self.solver.getName(exp.addr)
    
    def getUid(self, exp):
        return self.solver.getUid(exp.addr)

    def typeString(self, t):
        return self.solver.typeString(t.addr)

    def typeStringFromExpr(self, exp):
        return self.solver.typeStringFromExpr(exp.addr)

    def getBitSizeFromExpr(self, exp):
        return self.solver.getBitSizeFromExpr(exp.addr)

    def getKindString(self, kind):
        return self.solver.getKindString(kind)

    def kindString(self, exp):
        return self.solver.kindString(exp.addr)

    def getBoolFromBitvector(self, exp):
        return Expression(None, self, self.solver.getBoolFromBitvector(exp.addr))

    def getBitvectorFromBool(self, exp, bits=1):
        return Expression(None, self, self.solver.getBitvectorFromBool(exp.addr, bits))
    
    def skolemizeVar(self, exp, idx):
        return Expression(None, self, self.solver.skolemizeVar(exp.addr, idx), exp.signed)
    
    def skolemize(self, exp, boundVars, skolemVars):
        r_boundVars = []
        r_skolemVars = []
        for e in boundVars:
            r_boundVars.append(e.addr)
        for e in skolemVars:
            r_skolemVars.append(e.addr)
        return Expression(None, self, self.solver.skolemize(exp.addr, r_boundVars, r_skolemVars), exp.signed)
    
    def getInt(self, exp):
        return self.solver.getInt(exp.addr)

    #Logic functions
    def impliesExpr(self, hyp, concl):
        return Expression(None, self, self.solver.impliesExpr(hyp.addr, concl.addr))

    def iffExpr(self, exp1, exp2):
        return Expression(None, self, self.solver.iffExpr(exp1.addr, exp2.addr))

    def distinctExpr(self, arr_expr):
        tmp=[]
        for e in arr_expr:
            tmp.append(e.addr)
        return Expression(None, self, self.solver.distinctExpr(tmp))

    def forallExpr(self, Bvars, exp):
        tmp=[]
        for e in Bvars:
            tmp.append(e.addr)
        return Expression(None, self, self.solver.forallExpr(tmp, exp.addr))
    
    def existsExpr(self, Bvars, exp):
        tmp=[]
        for e in Bvars:
            tmp.append(e.addr)
        return Expression(None, self, self.solver.existsExpr(tmp, exp.addr))

    def lambdaExpr(self, Bvars, exp):
        tmp=[]
        for e in Bvars:
            tmp.append(e.addr)
        return Expression(None, self, self.solver.lambdaExpr(tmp, exp.addr))
    
    def iteExpr(self, ifpart, thenpart, elsepart):
        return Expression(None, self, self.solver.iteExpr(ifpart.addr, thenpart.addr, elsepart.addr))

    def trueExpr(self):
        return Expression(None, self, self.solver.trueExpr())

    def falseExpr(self):
        return Expression(None, self, self.solver.falseExpr())

    def boolNotExpr(self, exp):
        return Expression(None, self, self.solver.boolNotExpr(exp.addr))

    def boolAndExpr(self, exp1, exp2):
        return Expression(None, self, self.solver.boolAndExpr(exp1.addr, exp2.addr))

    def boolOrExpr(self, exp1, exp2):
        return Expression(None, self, self.solver.boolOrExpr(exp1.addr, exp2.addr))

    def boolXorExpr(self, exp1, exp2):
        return Expression(None, self, self.solver.boolXorExpr(exp1.addr, exp2.addr))
    
    #Order functions
    def ltExpr(self, exp1, exp2):
        return Expression(None, self, self.solver.ltExpr(exp1.addr, exp2.addr))

    def leExpr(self, exp1, exp2):
        return Expression(None, self, self.solver.leExpr(exp1.addr, exp2.addr))

    def gtExpr(self, exp1, exp2):
        return Expression(None, self, self.solver.gtExpr(exp1.addr, exp2.addr))

    def geExpr(self, exp1, exp2):
        return Expression(None, self, self.solver.geExpr(exp1.addr, exp2.addr))

    def sltExpr(self, exp1, exp2):
        return Expression(None, self, self.solver.sltExpr(exp1.addr, exp2.addr))

    def sleExpr(self, exp1, exp2):
        return Expression(None, self, self.solver.sleExpr(exp1.addr, exp2.addr))

    def sgtExpr(self, exp1, exp2):
        return Expression(None, self, self.solver.sgtExpr(exp1.addr, exp2.addr))

    def sgeExpr(self, exp1, exp2):
        return Expression(None, self, self.solver.sgeExpr(exp1.addr, exp2.addr))

    def eqExpr(self, exp1, exp2):
        return Expression(None, self, self.solver.eqExpr(exp1.addr, exp2.addr))

    def neExpr(self, exp1, exp2):
        return Expression(None, self, self.solver.neExpr(exp1.addr, exp2.addr))

    #Bit-Vector functions
    def UConstFromExpr(self, exp):
        return self.solver.UConstFromExpr(exp.addr)

    def constExpr(self, num, bits=32, signed=False):
        return Expression(None, self, self.solver.constExpr(num, bits), signed)

    def concatExpr(self, exp1, exp2):
        return Expression(None, self, self.solver.concatExpr(exp1.addr, exp2.addr))

    def extractExpr(self, exp, start, end):
        return Expression(None, self, self.solver.extractExpr(exp.addr, start, end))

    def boolExtractExpr(self, exp, bit):
        return Expression(None, self, self.solver.boolExtractExpr(exp.addr, bit))

    def signExtendExpr(self, exp, bits):
        return Expression(None, self, self.solver.signExtendExpr(exp.addr, bits))

    def zeroExtendExpr(self, exp, bits):
        return Expression(None, self, self.solver.zeroExtendExpr(exp.addr, bits))

    #the <bits> here might be an expression or a constant amount
    def leftRotateExpr(self, exp, bits):
        if isinstance(bits, Expression): bits=bits.addr
        return Expression(None, self, self.solver.leftRotateExpr(exp.addr, bits))

    #the <bits> here might be an expression or a constant amount
    def leftShiftExpr(self, exp, bits, finalsize=None):
        if isinstance(bits, Expression): bits=bits.addr
        return Expression(None, self, self.solver.leftShiftExpr(exp.addr, bits, finalsize))

    #the <bits> here might be an expression or a constant amount
    def rightArithmeticShiftExpr(self, exp, bits, finalsize=None):
        if isinstance(bits, Expression): bits=bits.addr
        return Expression(None, self, self.solver.rightArithmeticShiftExpr(exp.addr, bits, finalsize), exp.signed)

    #the <bits> here might be an expression or a constant amount
    def rightRotateExpr(self, exp, bits):
        if isinstance(bits, Expression): bits=bits.addr
        return Expression(None, self, self.solver.rightRotateExpr(exp.addr, bits))

    #the <bits> here might be an expression or a constant amount
    def rightShiftExpr(self, exp, bits, finalsize=None):
        if isinstance(bits, Expression): bits=bits.addr
        return Expression(None, self, self.solver.rightShiftExpr(exp.addr, bits, finalsize))

    def notExpr(self, exp):
        return Expression(None, self, self.solver.notExpr(exp.addr))

    def andExpr(self, exp1, exp2):
        return Expression(None, self, self.solver.andExpr(exp1.addr, exp2.addr))

    def orExpr(self, exp1, exp2):
        return Expression(None, self, self.solver.orExpr(exp1.addr, exp2.addr))

    def xorExpr(self, exp1, exp2):
        return Expression(None, self, self.solver.xorExpr(exp1.addr, exp2.addr))

    def negExpr(self, exp):
        return Expression(None, self, self.solver.negExpr(exp.addr))

    def addExpr(self, exp1, exp2, bits=None):
        return Expression(None, self, self.solver.addExpr(exp1.addr, exp2.addr, bits), exp1.signed and exp2.signed)

    def subExpr(self, exp1, exp2, bits=None):
        return Expression(None, self, self.solver.subExpr(exp1.addr, exp2.addr, bits), exp1.signed and exp2.signed)

    def umulExpr(self, exp1, exp2, bits=None):
        return Expression(None, self, self.solver.umulExpr(exp1.addr, exp2.addr, bits))

    def udivExpr(self, exp1, exp2):
        return Expression(None, self, self.solver.udivExpr(exp1.addr, exp2.addr))

    def uremExpr(self, exp1, exp2):
        return Expression(None, self, self.solver.uremExpr(exp1.addr, exp2.addr))

    def sdivExpr(self, exp1, exp2):
        return Expression(None, self, self.solver.sdivExpr(exp1.addr, exp2.addr), True)

    def sremExpr(self, exp1, exp2):
        return Expression(None, self, self.solver.sremExpr(exp1.addr, exp2.addr), True)

    def smodExpr(self, exp1, exp2):
        return Expression(None, self, self.solver.smodExpr(exp1.addr, exp2.addr), True)

    def smulExpr(self, exp1, exp2, bits=None):
        return Expression(None, self, self.solver.smulExpr(exp1.addr, exp2.addr, bits), True)

    def assignExpr(self, exp1, exp2, bits=None, endpos=0, pos=0, endbits=None):
        return Expression(None, self, self.solver.assignExpr(exp1.addr, exp2.addr, bits, endpos, pos, endbits))

    def dumpExpr(self, exp, recursive=False, calchash=False):
        tmp=self.solver.dumpExpr(exp.addr, recursive, calchash)
        self.crc=self.solver.crc
        return (tmp, exp.lang, exp.signed)
    
    def loadExpr(self, dump, recursive=False, varsdict=None):
        if varsdict:
            tmp={}
            for k,v in varsdict.iteritems():
                tmp[k]=v.addr
            varsdict=tmp
        tmp = Expression(None, self, self.solver.loadExpr(dump[0], recursive, varsdict))
        tmp.lang = dump[1]
        tmp.signed = dump[2]
        return tmp

    def getVarDependency(self, exp, return_name=False):
        tmp=self.solver.getVarDependency(exp.addr, return_name)
        if return_name:
            return tmp
        ret=[]
        for e in tmp:
            ret.append(Expression(None, self, e))
        return ret
    
    def hashExpr(self, exp):
        return self.solver.hashExpr(exp.addr)
    
    def mergeExpr(self, exp, varsdict):
        tmp={}
        for k,v in varsdict.iteritems():
            tmp[k]=v.addr
        return Expression(None, self, self.solver.mergeExpr(exp.addr, tmp), exp.signed)
    
    def concreteModelGenerator(self, exp):
        for item in self.solver.concreteModelGenerator(exp.addr):
            for x in xrange(0, len(item)):
                item[x] = Expression(None, self, item[x], False, exp.lang)
            
            yield item
        return

def mymain():
    sol=PrettySolver()
    sol2=PrettySolver()
    
    v1 = sol.varExpr("v1")
    d = v1.dump()
    
    newvar = sol.createExpression()
    newvar.load(d)
    
    newvar+="v1" #mixed operands work as expected
    
    print v1 > newvar #non-boolean context, it returns a comparision expression
    if v1 == v1: #boolean context, a queryFormula is executed here
        print "GRINGO!"
    
    #sol.assertFormula(v1 == 1) #mixed operands, 1 converted to constExpr
    
    #print newvar[v1] #returns a 1 bit extraction on index 1 because the previous assert
    
    newvar2 = sol2.createExpression()
    newvar2.load(d)
    
    a=newvar2 + v1
    c=v1 + v1
    
    print a.psolver
    print v1.psolver
    
    b={}
    b[a]=True
    print hash(a)
    print a
    print c
    print hash(c)
    
    print "******"
    a=sol.constExpr(0xcafecafe)
    
    
    print (a*2)[0:32]
    print repr(a)

#mymain()
