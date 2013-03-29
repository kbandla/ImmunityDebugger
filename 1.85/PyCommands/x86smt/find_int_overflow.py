import getopt

from immlib import *

from x86smt.sequenceanalyzer import SequenceAnalyzer
from codegraph import CodeStructureAnalyzer
from pathgenerator import PathGenerator
from x86smt.pathwalker import PathWalker
from x86smt.pathwalker import UnsatPathConditionException
from x86smt.bugcheckers.intoverflow import IntOverflowChecker

NAME = 'find_int_overflow'
DEBUG = False

def usage(imm):
    imm.log("!%s" % NAME)
    imm.log("   -s start_addr [hex]")

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

def main(args):
    imm = Debugger()
    imm.log("### %s ###" % NAME)
    
    start_addr = None

    try:
        opts, argo = getopt.getopt(args, "s:e:")
    except getopt.GetoptError, reason:
        imm.log("Exception when parsing arguments: %s" % reason)
        usage(imm)
        return "Error parsing arguments. See log for details"
        
    for o, a in opts:
        if o == "-s":
            start_addr = int(a, 16)
        else:
            usage(imm)
            return "Unknown option %s" % o

    if start_addr is None:
        usage(imm)
        return "You must specify a starting address"

    csa = CodeStructureAnalyzer(imm, start_addr)
    bb_graph = csa.getBasicBlockGraph()

    pg = PathGenerator(bb_graph.basic_blocks, bb_graph.bb_out_edges)
    pg.imm = imm

    false_path_cnt = 0
    path_cnt = 0
    
    for path in pg.generatePaths(start_addr):
        path_cnt += 1
        p_walker = PathWalker(imm, debug=DEBUG)
        checker = IntOverflowChecker(imm, debug=DEBUG)
        
        try:
            p_walker.walk(path, analysis_mods=[checker])
        except UnsatPathConditionException, e:
            false_path_cnt += 1
            continue

        analysis_results = p_walker.getAnalysisResults(checker=checker)
        for bug_check_res in analysis_results:
            imm.log("Potential integer overflow @ %s" % \
                    bug_check_res.addr, bug_check_res.addr)

    imm.log("%d/%d paths were feasible and checked" % \
            (path_cnt - false_path_cnt, path_cnt))

    
    return "Finished. Check log for details"
