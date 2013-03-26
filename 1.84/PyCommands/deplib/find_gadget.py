import pickle
import getopt

from x86smt.sequenceanalyzer import SequenceAnalyzer, MyDebugger
from immlib import *

"""
This script takes a pickle file describing a set of candidate gadgets
and looks for a sequence that satisfies the constraints we specify.

For now it takes a destination register (-d) and a src register (-s) or
value (-v) that we wish to put in the destination. The default mode is
to search for generic gadgets, that is those which regardless of the 
context will satisfy the constraints. In other words we look for a 
valid formula. 

e.g. !find_gadget -g Secur32.dll_gadgets.pkl -d EAX -v 0x0

(Finds instructions like xor eax, eax; ret; among other things)

!find_gadget -g Secur32.dll_gadgets.pkl -d EAX -s [EAX+10]
!find_gadget -g Secur32.dll_gadgets.pkl -d EAX -s EAX+10

(The first finds gadgets that move the value at [EAX+10] into EAX. 
Where 10 is in hex btw. The second looks for those that move the 
number given by adding 0x10 to EAX into EAX)

By passing the -c flag we can search for context specific gadgets. Such
a gadget is one which specifies the constraints given the current 
context of register values and memory state. In this case we look for
a satisfiable formula.

For now there is no way to dereference a memory location in the 
paramaters but that will be added.

e.g. !find_Gadget -g Secur32.dll_gadgets.pkl -d ESP -v 0x7fffc -c -a

(Finds instruction sequences that end with 0x7fffc in ESP given the
 current context. pop edi; pop esi; pop ebx; pop ebp; retn 24; for 
 example if ESP currently contains 0x7ffc4)

"""

DEBUG = False
VALID_REGISTERS = ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP",
                   "ESP"]
DEBUG = False
START = "### find_gadgets ###"

class InvalidLocationException(Exception):
    pass

def usage(imm):
    imm.log("!find_gadget")
    imm.log("    -g gadget_file")
    imm.log("    -d destination [Register or memory location " + \
            "referenced as [REG +/- CONST]]")
    imm.log("    -s source [As above. -s and -v are mutually " + \
            "       exclusive]")
    imm.log("    -v hex value, or range of the form start:end")
    imm.log("    -w value_width [1-32]")
    imm.log("    -p preserve_list [A list of registers that should")
    imm.log("       have the same value after the gadget as before]")
    imm.log("    -a [flag, if specified we try to find")
    imm.log("       all possible satisfying gadgets. Otherwise we")
    imm.log("       stop after the first is found]")
    imm.log("    -c [flag, if specified then we search for context")
    imm.log("       specific gadgets instead of generic ones.]")

def log_traceback(imm):
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

def get_location_expr(imm, sa, loc_str, width):
    """
    @type loc_str: String
    @param loc_str: A string specifying a register or memory location

    @rtype: Expression 
    @return: An expression denoting the location given by loc_str
    """

    expr = None
    is_mem_ref = False
    solver = sa.state.solver
        
    if loc_str[0] == '[' and loc_str[-1] == ']':
        is_mem_ref = True
        loc_str = loc_str[1:-1]

    if loc_str.upper() in VALID_REGISTERS:
        expr = sa.state.regs[loc_str.upper()]

    if loc_str.find('+') != -1:
        expr_list = loc_str.split('+')
        if len(expr_list) > 2 or expr_list[0] not in VALID_REGISTERS:
            return None
        reg_expr = sa.state.regs[expr_list[0].upper()]

        const = 0
        try:
            const = int(expr_list[1], 16)
        except ValueError:
            imm.log("Invalid constant in expression %s" % loc_str)
            return None
        
        const_expr = solver.constExpr(const)
        expr = solver.addExpr(reg_expr, const_expr)
    elif loc_str.find('-') != -1:
        expr_list = loc_str.split('-')
        if len(expr_list) > 2 or expr_list[0] not in VALID_REGISTERS:
            return None
        reg_expr = sa.state.regs[expr_list[0].upper()]

        const = 0
        try:
            const = int(expr_list[1], 16)
        except ValueError:
            imm.log("Invalid constant in expression %s" % loc_str)
            return None
        
        const_expr = solver.constExpr(const)
        expr = solver.subExpr(reg_expr, const_expr)

    expr = solver.simplify(expr)

    if is_mem_ref:
        expr = sa.getMemoryStateFromSolverState(expr, width)

    return expr
            
def find_gadgets(imm, gadget_pkl_name, dest, src, val_start, val_end, 
        val_width=32, find_all=False, generic=True, 
        preserve_regs=None):
    gadget_cnt = 0
    shortest_gadget = None
    r_model = m_model = f_model = None
             
    if not generic:
        # Fix the current value of all registers
        r_model = imm.getRegs()
        # Use concrete memory values
        m_model = True
        # No flag modelling for now
        f_model = None

    dump_file = open(gadget_pkl_name, 'rb')
    gadget_cnt = 0
    useful_gadget_cnt = 0
    done_processing = False

    while not done_processing:
        try:
            gadgets = cPickle.load(dump_file)
            gadget_cnt += len(gadgets)
        except EOFError:
            break
            
        for gadget in gadgets:
            sa = SequenceAnalyzer(imm, r_model, f_model, m_model)
            sa._debug = DEBUG 
            solver = sa.state.solver
            
            in_regs = {}
            in_out_exprs = []
            preserve_expr = None
            
            if preserve_regs is not None:
                for reg in preserve_regs:
                    if reg not in VALID_REGISTERS:
                        imm.log(
                            "%s is not a valid preserve register" % \
                            reg)
                        return "Error. See log"
                    in_regs[reg] = sa.state.regs[reg]        

            src_expr = None
            if val_start is None:
                src_expr = get_location_expr(imm, sa, src, val_width)
                if src_expr is None:
                    msg = "%s is not a valid source" % src
                    imm.log("%s" % msg)
                    raise InvalidLocationException(msg)

            x = sa.analyze(gadget.addr, depth=gadget.ins_cnt)
            if not x:
                continue
            
            # If there are registers whos value we want preserved after 
            # the gadget has ran then build an expression for this
            if preserve_regs is not None:
                for reg in preserve_regs:
                    out_reg = sa.state.regs[reg]
                    expr = solver.eqExpr(out_reg, in_regs[reg])
                    in_out_exprs.append(expr)

                preserve_expr = in_out_exprs[0]
                for expr in in_out_exprs[1:]:
                    preserve_expr = solver.boolAndExpr(
                            preserve_expr, expr)

            dest_expr = get_location_expr(imm, sa, dest, val_width)
            if dest_expr is None:
                msg = "%s is not a valid destination" % dest
                imm.log("%s" % msg)
                raise InvalidLocationException(msg)
                
            rel_expr = None
            if src_expr is None:
                # We're using constants not a register/mem location
                if val_end is None:
                    # Single value
                    src_expr = solver.constExpr(val_start, val_width)
                    rel_expr = solver.eqExpr(dest_expr, src_expr)
                else:
                    # Range
                    start_expr = solver.geExpr(dest_expr,
                            solver.constExpr(val_start))
                    end_expr = solver.leExpr(dest_expr,
                            solver.constExpr(val_end))
                    rel_expr = solver.boolAndExpr(start_expr,
                            end_expr)
            else:
                # Equality with a register or mem location
                rel_expr = solver.eqExpr(dest_expr, src_expr)

            if preserve_expr is not None:
                rel_expr = solver.boolAndExpr(preserve_expr, 
                        rel_expr)

            if generic:
                # Check for validity.
                res = solver.queryFormula(rel_expr)
                if res == 1:
                    useful_gadget_cnt += 1
                    imm.log("Found gadget at %x of length %d" % \
                            (gadget.addr, gadget.ins_cnt), gadget.addr)
                    if not find_all:
                        imm.log("To find all gadgets specify -a")
                        done_processing = True
                        break
                    else:
                        if shortest_gadget is None:
                            shortest_gadget = gadget
                        else:
                            if gadget.ins_cnt < shortest_gadget.ins_cnt:
                                shortest_gadget = gadget
            else:
                # Check for satisfiability
                res = solver.checkUnsat(rel_expr)
                if res == 0:
                    useful_gadget_cnt += 1
                    imm.log("Found gadget at %x of length %d" % \
                            (gadget.addr, gadget.ins_cnt), gadget.addr)
                    if not find_all:
                        imm.log("To find all gadgets specify -a")
                        done_processing = True
                        break
                    else:
                        if shortest_gadget is None:
                            shortest_gadget = gadget
                        else:
                            if gadget.ins_cnt < shortest_gadget.ins_cnt:
                                shortest_gadget = gadget

    dump_file.close()
    imm.log("Processed %d gadgets" % gadget_cnt)

    return (useful_gadget_cnt, shortest_gadget) 

def main(args):
    imm = Debugger()
    imm.log("%s" % START)

    gadget_pkl_name = None
    dest = None
    src = None
    val_start = None
    val_end = None
    val_width = 32
    preserve_regs = None
    find_all = False
    context_specific = False
    
    try:
        opts, argo = getopt.getopt(args, "g:d:s:v:w:p:ac",
                                   ["gadget_file=",
                                    "dest=",
                                    "src="
                                    "value=",
                                    "width=",
                                    "preserve_regs=",
                                    "find_all",
                                    "context_specific",
                                    ])
    except getopt.GetoptError, reason:
        imm.log("Exception when parsing arguments: %s" % reason)
        log_traceback(imm)
        return "Error parsing arguments. See log for details"

    for o, a in opts:
        if o == "-g":
            gadget_pkl_name = a
        elif o == "-d":
            dest = a
        elif o == "-s":
            src = a
        elif o == "-v":
            val_range = a.split(':')
            if len(val_range) == 2:
                val_start = val_range[0]
                val_end = val_range[1]
                try:
                    val_start = int(val_start, 16)
                    val_end = int(val_end, 16)
                except ValueError:
                    usage(imm)
                    return "Invalid start or end value in %s" % a

                if val_start > val_end:
                    usage(imm)
                    return "Start value must be smaller than end value"
            else:
                try:
                    val_start = int(a, 16)
                except:
                    usage(imm)
                    return "Invalid value. Must be of the form 0xAABBCCDD"
        elif o == "-w":
            try:
                val_width = int(a)
            except:
                usage(imm)
                return "The value width must be between 1 and 32"
        elif o == "-p":
            preserve_regs = set()
            [preserve_regs.add(reg.strip()) for reg in a.split(",")]
        elif o == "-a":
            find_all = True
        elif o == "-c":
            context_specific = True
        else:
            usage(imm)
            return "Unhandled option %s" % o

    if gadget_pkl_name is None:
        usage(imm)
        return "You must specify a pickle file containing gadgets"

    if dest is None:
        usage(imm)
        return "You must specify a destination register or " + \
               "memory location"

    if (val_start is None and src is None) or \
       (val_start is not None and src is not None):
        usage(imm)
        return "You must specify a value xor a source"

    if val_width < 1 or val_width > 32:
        usage(imm)
        return "The value width must be between 1 and 32"
    
    imm.log("Importing gadget information from %s" % gadget_pkl_name)
    imm.log("Preserving registers: %s" % preserve_regs)

    dest_set = None 
    if dest == "ANY":
        dest_set = set(VALID_REGISTERS)
    else:
        dest_set = set([dest])
    
    if preserve_regs is not None:
        dest_set.difference_update(preserve_regs)

    if context_specific and (dest.find('[') != -1 or (src is not None \
        and src.find('['))):
        usage(imm)
        return "Don't use -c with a memory reference as dst or src"

    for dest in dest_set:
        imm.log("Searching for gadget to set destination: %s" % dest)
        gadget_cnt = 0
        if context_specific:
            ctxt_time_start = time.time()
            imm.log("=== Finding context specific gadgets ===")
            gadget_cnt, spec_short = find_gadgets(imm, gadget_pkl_name, 
                                            dest, src, val_start, val_end,
                                            val_width=val_width,
                                            find_all=find_all,
                                            generic=False,
                                            preserve_regs=preserve_regs)
            ctxt_time_end = time.time()
            imm.log("Context specific gadget search time: %f" % \
                    (ctxt_time_end - ctxt_time_start))
            if gadget_cnt == 1:
                return "1 context specific gadget found"
            elif gadget_cnt != 0:
                if spec_short is not None:
                    imm.log(
                        "Shortest gadget sequence: %d instructions" % \
                        spec_short.ins_cnt, spec_short.addr)
                return "%d context specific gadgets found" % gadget_cnt
        else:
            spec_time_start = time.time()
            imm.log("=== Finding generic gadgets ===")
            gadget_cnt, gen_short = find_gadgets(imm, gadget_pkl_name, 
                                        dest, src, val_start, val_end,
                                        val_width=val_width,
                                        find_all=find_all,
                                        generic=True,
                                        preserve_regs=preserve_regs)
            spec_time_end = time.time()
            imm.log("Generic specific gadget search time: %f" % \
                    (spec_time_end - spec_time_start))
                    
            if gadget_cnt == 1:
                return "1 generic gadget found"
            elif gadget_cnt != 0:
                if gen_short is not None:
                    imm.log(
                        "Shortest gadget sequence: %d instructions" % \
                        gen_short.ins_cnt, gen_short.addr)
                return "%d generic gadgets found" % gadget_cnt

    return "No satisfying gadgets found"

