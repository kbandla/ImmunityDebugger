import re
import sys
import getopt
import traceback

from x86smt.sequenceanalyzer import SequenceAnalyzer
from immlib import *

DEBUG = False
VALID_RELATIONS = ['<', '>', '=', '!=', '<=', '>=']

def usage(imm):
    imm.log("!symexec")
    imm.log("   -s start_addr [hex]")
    imm.log("   -e end_addr [hex]")
    imm.log("   -r output_reg [Valid register name e.g. EAX]")
    imm.log("   -n relation [(In)Equality symbol e.g. %s]" %
            VALID_RELATIONS)
    imm.log("      (Prefix the above symbol with an 's' for signed comparisons)")
    imm.log("   -v output_val [hex]")
    imm.log("   -w val_width [0-32, default=32]")
    imm.log("   -u user_regs [Comma separated list of user controlled registers e.g EAX,EBX]")

def logTraceback(imm):
    imm.log("Traceback:")
    
    tb = sys.exc_info()[2]
    for line in traceback.extract_tb(tb):
        f_name = line[0]
        line_num = line[1]
        function = line[2]
        src_line = line[3]
        imm.log("File %s:%d" % (f_name, line_num))
        imm.log("    Function: %s" % function)
        imm.log("    Code: %s" % src_line)    
    
def binStrToUint32(s):
    exp = len(s)
    val = 0
    for i in range(0, exp):
        if int(s[i]) & 1:
            val += 2**(exp - 1 - i)
        
    return val

def relationToExpr(sa, r, lhs, rhs, signed=False):
    solver = sa.state.solver
    exp = None

    if r == '<':
        if signed:
            exp = solver.sltExpr(lhs, rhs)
        else:
            exp = solver.ltExpr(lhs, rhs)
    elif r == '>':
        if signed:
            exp = solver.sgtExpr(lhs, rhs)
        else:
            exp = solver.gtExpr(lhs, rhs)
    elif r == '=':
        exp = solver.eqExpr(lhs, rhs)
    elif r == '!=':
        exp = solver.neExpr(lhs, rhs)
    elif r == '<=':
        if signed:
            exp_1 = solver.sltExpr(lhs, rhs)
        else:
            exp_1 = solver.ltExpr(lhs, rhs)
            
        exp_2 = solver.eqExpr(lhs, rhs)
        exp = solver.boolOrExpr(exp_1, exp_2)
    elif r == '>=':
        if signed:
            exp_1 = solver.sgtExpr(lhs, rhs)
        else:
            exp_1 = solver.gtExpr(lhs, rhs)
            
        exp_2 = solver.eqExpr(lhs, rhs)
        exp = solver.boolOrExpr(exp_1, exp_2)

    return exp

def main(args):
    imm = Debugger()

    start_addr = None
    end_addr = None
    output_reg = None
    relation = None
    signed = False
    output_val = None
    user_regs = None
    val_width = 32

    try:
        opts, argo = getopt.getopt(args, "s:e:r:n:v:w:u:",
                                   ["start_addr=",
                                    "end_addr=",
                                    "output_reg=",
                                    "relation=",
                                    "output_val=",
                                    "val_width=",
                                    "user_regs="])
    except getopt.GetoptError, reason:
        imm.log("Exception when parsing arguments: %s" % reason)
        log_traceback(imm)
        return "Error parsing arguments. See log for details"
    
    for o, a in opts:
        if o == "-s":
            try:
                start_addr = int(a, 16)
            except:
                usage(imm)
                return "Invalid start address"
        elif o == "-e":
            try:
                end_addr = int(a, 16)
            except:
                usage(imm)
                return "Invalid end address"
        elif o == "-r":
            output_reg = a
        elif o == "-n":
            relation = a
            if relation[0] == 's':
                signed = True
                relation = relation[1:]
                
            if relation not in VALID_RELATIONS:
                usage(imm)
                return "%s is not a valid relation (%s)" % \
                        (relation, VALID_RELATIONS)
        elif o == "-v":
            try:
                output_val = int(a, 16)
            except:
                usage(imm)
                return "Invalid register value"
        elif o == "-w":
            val_width = int(a, 10)
        elif o == "-u":
            user_regs = set()
            [user_regs.add(reg.strip()) for reg in a.split(",")]
                 
    if start_addr is None:
        usage(imm)
        return "You must specify a start address"
                
    if end_addr is None:
        usage(imm)
        return "You must specify an end address"

    if end_addr < start_addr:
        log_msg = ("You twit! End address %s is less than the " + \
                   "start address %s") % (hex(end_addr),
                                          hex(start_addr))
        imm.log("%s" % log_msg)
        return log_msg
 
    if output_reg is None:
        usage(imm)
        return "You must specify an output register"

    if relation is None:
        usage(imm)
        return "You must specify a relation"
    
    if output_val is None:
        usage(imm)
        return "You must specify a desired output value (in hex)"
    
    if user_regs is None or len(user_regs) == 0:
        usage(imm)
        return "You must specify one or more user defined registers"
    
    imm.log("Analyzing from %s to %s" % (hex(start_addr),
                                         hex(end_addr)))
    imm.log("Solving for %s %s %s" % (output_reg, relation,
                                      hex(output_val)))
    imm.log("Assuming %s are user controlled" % \
            (', '.join(user_regs)))
    
    r_model = imm.getRegs()
    for reg in user_regs:
        if reg in r_model:
            del r_model[reg]
            
    f_model = None
    m_model = True
    
    sa = SequenceAnalyzer(imm, r_model, f_model, m_model)
    solver = sa.state.solver
    sa._debug = DEBUG

    imm.markBegin()
    sa.analyze(start_addr, 100, stopEIP=end_addr)   
    
    imm.log("Elapsed time: %d secs" % imm.markEnd())
    reg_exp = sa.state.regs[output_reg]
    const_exp = solver.constExpr(output_val, val_width)
    rel_exp = relationToExpr(sa, relation, reg_exp, const_exp, signed)

    res = solver.checkUnsat(rel_exp)

    if res == 0:
        imm.log("Result: SAT")
        imm.log("Model:")
        model = solver.getConcreteModel()

        strip_p = '[()=]'
        strip_r = re.compile(strip_p)
        
        for expr in model:
            expr_str = solver.exprString(expr)
            expr_data = re.sub(strip_r, ' ', expr_str).strip().split()
            var_name = expr_data[0]
            var_val = expr_data[1]

            if var_name.startswith("_"):
                imm.log("%s" % str(expr_data))
            else:
                i_val = binStrToUint32(var_val[4:])
                imm.log("%s = %s" % (var_name, hex(i_val)))
    else:
        imm.log("Result: UNSAT")

    return "Check log window for results"
