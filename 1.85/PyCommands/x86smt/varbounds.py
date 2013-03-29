import sys
import getopt
import traceback

from x86smt.sequenceanalyzer import SequenceAnalyzer, MyDebugger
from immlib import *

DEBUG = False
LOWER = 0
UPPER = 2**32 - 1
RANGE_MIN = 2**16

class AddressRange:

    def __init__(self, start, end):
        self.start = start
        self.end = end

def usage(imm):
    imm.log("!varbounds")
    imm.log("   -s start_addr [hex]")
    imm.log("   -e end_addr [hex]")
    imm.log("   -r output_reg [Valid register name e.g. EAX]")
    imm.log("   -u user_regs [Comma separated list of user controlled registers e.g EAX,EBX]")
    imm.log("   -v value_range [colon separated bounds to investigated default=%s:%s]" % (hex(LOWER), hex(UPPER)))
    imm.log("   -a range_size [Size of buckets to split ranges into as part of the first pass, default=%d" % RANGE_MIN)
    imm.log("   -t timeout [A timeout in seconds after which we abort, default=None]")
    imm.log("   -p precise [If specified then we look for exact values instead of ranges, default=True]")

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

def boundsExpr(sa, var_expr, lower_expr, upper_expr):
    solver = sa.state.solver

    ge_expr = solver.geExpr(var_expr, lower_expr)
    le_expr = solver.leExpr(var_expr, upper_expr)
    and_expr = solver.boolAndExpr(ge_expr, le_expr)
    
    return and_expr

def mergeRanges(range_list):
    range_len = len(range_list)
    
    if range_list == 0:
        return []

    idx = range_len - 1
    while idx > 0:
        curr = range_list[idx]
        prev = range_list[idx - 1]

        if curr.start == prev.end + 1:
            prev.end = curr.end
            range_list.pop()

        idx -= 1
        
    return range_list

def mergeValues(value_list):
    range_list = []
    idx = len(value_list) - 1

    if idx == 0:
        range_list.append(AddressRange(value_list[0], value_list[0]))

    curr_range = AddressRange(value_list[idx], value_list[idx])
    while idx > 0:
        curr = value_list[idx]
        prev = value_list[idx - 1]

        if prev + 1 == curr:
            curr_range.start = prev
        else:
            range_list.append(curr_range)
            curr_range = AddressRange(prev, prev)

        idx -= 1

    range_list.append(curr_range)
    return range_list

def logRanges(imm, ranges):
    for r in ranges:
        lower = r.start
        upper = r.end
        imm.log("    %s:%s" % (hex(lower), hex(upper)))

def findSatValues(imm, sa, output_reg, candidate_range,
                    start=None, timeout=None):
    lower = candidate_range.start
    upper = candidate_range.end
    solver = sa.state.solver

    sat_values = set()
    unsat_values = set()
    for val in range(lower, upper+1):
        if timeout is not None and time.time() - start >= timeout:
            break
        
        # Preserve solver state
        sa.push()
       
        reg_expr = sa.state.regs[output_reg]
        const_expr = solver.constExpr(val)
        eq_expr = solver.eqExpr(reg_expr, const_expr)
        res = solver.checkUnsat(eq_expr)

        if res == 0:
            sat_values.add(val)
        else:
            unsat_values.add(val)

        # Restore solver state
        sa.pop()
        
    return (sat_values, unsat_values)

def main(args):
    imm = MyDebugger()

    start_addr = None
    end_addr = None
    output_reg = None
    lower = LOWER
    upper = UPPER
    user_regs = None
    timeout = None
    range_size = RANGE_MIN
    precise_mode = False 

    try:
        opts, argo = getopt.getopt(args, "s:e:r:u:v:a:t:p",
                                   ["start_addr=",
                                    "end_addr=",
                                    "output_reg=",
                                    "value_range=",
                                    "user_regs=",
                                    "range_size",
                                    "timeout="
                                    "precise"])
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
                return "Invalid start address %s" % a
        elif o == "-e":
            try:
                end_addr = int(a, 16)
            except:
                usage(imm)
                return "Invalid end address %s" % a
        elif o == "-r":
            output_reg = a
        elif o == "-v":
            tmp = a.split(':')
            if len(tmp) != 2:
                usage(imm)
                return "Invalid value range %s" % a

            try:
                lower = int(tmp[0], 16)
            except ValueError:
                usage(imm)
                return "Invalid lower bound %s" % tmp[0]

            try:
                upper = int(tmp[1], 16)
            except ValueError:
                usage(imm)
                return "Invalid upper bound %s" % tmp[1]

            if not (lower < upper):
                usage(imm)
                return "%s is not less than %s you twit!" % (hex(lower), hex(upper))            
        elif o == "-u":
            user_regs = set()
            [user_regs.add(reg.strip()) for reg in a.split(",")]
        elif o == "-a":
            try:
                range_size = int(a)
            except ValueError:
                return "Invalid range size %s" % a
        elif o == "-t":
            try:
                timeout = int(a)
            except ValueError:
                usage(imm)
                return "Invalid timeout value %s" % a
        elif o == "-p":
            precise_mode = True
                 
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
    
    if user_regs is None or len(user_regs) == 0:
        usage(imm)
        return "You must specify one or more user defined registers"
    
    imm.log("Analyzing from %s to %s" % (hex(start_addr),
                                         hex(end_addr)))
    imm.log("Investigating range %s:%s for register %s" % \
            (hex(lower), hex(upper), output_reg))
    imm.log("Assuming %s are user controlled" % \
            (', '.join(user_regs)))
    
    r_model = imm.getRegs()
    for reg in user_regs:
        if reg in r_model:
            del r_model[reg]
            
    f_model = None
    m_model = True
    
    imm.markBegin()
    
    imm.log("Conversion to SMT done in %d secs" % imm.markEnd())

    sat_ranges = []
    unsat_ranges = []
    ranges_to_test = []
    ranges_to_test.append(AddressRange(lower, upper))
    sa = SequenceAnalyzer(imm, r_model, f_model, m_model)
    solver = sa.state.solver
    sa._debug = DEBUG 
    sa.analyze(start_addr, stopEIP=end_addr)

    total_queries = 0
    start = time.time()
    while True:
        if timeout is not None and time.time() - start >= timeout:
            imm.log("Timeout of %d seconds expired during first phase" % timeout)
            break
        
        # Preserve solver state
        sa.push()
        
        reg_expr = sa.state.regs[output_reg]
        try:
            addr_range = ranges_to_test.pop()
        except IndexError:
            sa.pop()
            break

        lower = addr_range.start
        upper = addr_range.end
        
        imm.log("Checking range %s:%s" % (hex(lower), hex(upper)))
        lower_expr = solver.constExpr(lower)
        upper_expr = solver.constExpr(upper)
        rel_expr = boundsExpr(sa, reg_expr, lower_expr,
                                           upper_expr)
        res = solver.checkUnsat(rel_expr)
        total_queries += 1
        
        if res == 0:
            imm.log("SAT: %s <= VAL <= %s" % (hex(lower), hex(upper)))
            diff = upper - lower 
            if diff <= range_size:
                sat_ranges.append(addr_range)
            else:
                mid = lower + diff/2 
                ranges_to_test.append(AddressRange(lower, mid))
                ranges_to_test.append(AddressRange(mid + 1, upper))
        else:
            imm.log("UNSAT: %s <= VAL <= %s" % (hex(lower), hex(upper)))
            unsat_ranges.append(addr_range)

        # Restore solver state
        sa.pop()

    sat_ranges = mergeRanges(sat_ranges)
    unsat_ranges = mergeRanges(unsat_ranges)
    
    imm.log("** Possible ranges for %s **" % output_reg)
    logRanges(imm, sat_ranges)

    if precise_mode and timeout is not None and \
       time.time() - start < timeout:
        imm.log("Querying ranges...")
        sat_values = []
        unsat_values = []
        for candidate_range in sat_ranges:
            sat, unsat = findSatValues(imm, sa, output_reg,
                                         candidate_range, start,
                                         timeout)

            total_queries += len(sat)
            total_queries += len(unsat)
            
            sat_values.extend(sat)
            unsat_values.extend(unsat)

            if timeout is not None and time.time() - start >= timeout:
                imm.log("Timeout of %d seconds expired during second phase" % timeout)
                break

        imm.log("** Valid values for %s (%d)**" % (output_reg, len(sat_values)))
        precise_sat_ranges = mergeValues(sat_values)
        logRanges(imm, precise_sat_ranges)
        
        imm.log("** Invalid values for %s (%d) **" % (output_reg, len(unsat_values)))
        precise_unsat_ranges = mergeValues(unsat_values)
        logRanges(imm, precise_unsat_ranges)
    else:
        required_queries = 0
        for candidate_range in sat_ranges:
            required_queries += (candidate_range.end -
                                 candidate_range.start)
        imm.log("Precise results would require %d more queries" % \
                required_queries)
        
    end = time.time()

    imm.log("%d queries were made to the solver" % total_queries)
    return "Processing completed in %.3f seconds. Check log window." % \
        (end - start)
