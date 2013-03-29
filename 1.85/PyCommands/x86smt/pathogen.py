import getopt
import traceback
from immlib import *

from codegraph import CodeStructureAnalyzer
from pathgenerator import PathGenerator
from x86smt.pathwalker import PathWalker
from x86smt.pathwalker import UnsatPathConditionException

NAME = "pathogen.py"
    
def usage(imm):
    imm.log("!pathogen")
    imm.log("   -s start_addr [hex]")
    imm.log("   -p prune_paths [use solver to prune paths]")

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
        
def main(args):
    imm = Debugger()
    imm.log("### %s ###" % NAME)
    
    start_addr = None
    prune_paths = False

    try:
        opts, argo = getopt.getopt(args, "s:p")
    except getopt.GetoptError, reason:
        imm.log("Exception when parsing arguments: %s" % reason)
        usage(imm)
        return "Error parsing arguments. See log for details"
        
    for o, a in opts:
        if o == "-s":
            start_addr = int(a, 16)
        elif o == "-p":
            prune_paths = True
        else:
            usage(imm)
            return "Unknown option %s" % o

    if start_addr is None:
        usage(imm)
        return "You must specify a starting address"

    csa = CodeStructureAnalyzer(imm, start_addr)
    bb_graph = csa.getBasicBlockGraph()
    bb_graph.log(imm)
    
    imm.log("** FORWARD PATHS **")
    
    # Use the path generator to dump all possible paths
    pg = PathGenerator(bb_graph.basic_blocks, bb_graph.bb_out_edges)
    pg.imm = imm
    
    cnt = 0
    feasible_paths = []
    for path in pg.generatePaths(start_addr):
        cnt += 1

        imm.log("%s" % str(path))
        if not prune_paths:
            continue

        p_walker = PathWalker(imm, debug=True)
        try:
            p_walker.walk(path)
            feasible_paths.append(path)
        except UnsatPathConditionException, e:
            imm.log("%s" % str(e))

    ret_str = ""
    if prune_paths:
        imm.log("** FEASIBLE PATHS **")
        for path in feasible_paths:
            imm.log("%s" % str(path))

        f_cnt = len(feasible_paths)
        ret_str =  "%d feasible paths out of %d candidates" % (f_cnt, cnt)
    else:
        ret_str = "%d candidate paths, use -p to prune" % cnt

    return ret_str

