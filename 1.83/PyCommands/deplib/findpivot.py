from x86smt.sequenceanalyzer import MyDebugger
import getopt
from immlib import *
from deplib.libfinder import GadgetFinder
from x86smt.prettysolver import *
from x86smt.sequenceanalyzer import StateMachine
from immlib import *


def usage(imm):
    imm.log("!findpivot")
    imm.log("Defaults between square brackets")
    imm.log("  -e               = An expression for memory controlled by the attacker to pivot to.")
    imm.log("  -r               = How many results to show. [100]")
    imm.log("  -t sqlite3|mysql = Type of DB [sqlite3]")
    imm.log("  -n dbname        = DB name ['gadgets.sq3' if sqlite3 or 'gadgets' if mysql]")
    imm.log("  -h host          = host for the DB connection [127.0.0.1]")
    imm.log("  -u username      = username for the DB connection")
    imm.log("  -p password      = password for the DB connection")
    imm.log("  -m module        = Module to use [use all modules in the DB]")
    imm.log("  -d               = Activate debugging")
    imm.log("  -l               = Log everything in a file")
    imm.log("")
    imm.log("multiple -m options are accepted")
    imm.log("a module option can receive the version to use too, for example: ntdll.dll|5.1.2600.5512")
    imm.log("")
    imm.log("Expression examples (basically a python expression using PrettySolver):")
    imm.log("EAX: means we control the memory area pointed by EAX")
    imm.log("mem(EBP)+4: we control the memory area found after dereferencing EBP and adding 4")

def main( args ):
    imm = Debugger()
    
    try:
        opts, argo = getopt.getopt(args, "e:r:t:n:h:u:p:m:dl")
    except getopt.GetoptError, reason:
        imm.log("[!] Exception when parsing arguments: %s" % reason)
        usage(imm)
        return "Error parsing arguments. See log for details"

    dbtype = dbname = host = username = passwd = exp = None
    debug = logfile = False
    modules=[]
    results_count=100
    for o, a in opts:
        if o == "-e":
            exp = a
        elif o == "-r":
            results_count = a
        elif o == "-t":
            dbtype = a
        elif o == "-n":
            dbname = a
        elif o == "-h":
            host = a
        elif o == "-u":
            username = a
        elif o == "-p":
            passwd = a
        elif o == "-m":
            modules.append(a.split("|"))
        elif o == "-d":
            debug=True
        elif o == "-l":
            logfile=True
        else:
            usage(imm)
            return "Unknown option"
    
    if not exp:
        usage(imm)
        imm.log("[!] -e is mandatory")
        return "Error, check script usemode"
    
    if logfile:
        imm = MyDebugger(template="findpivot-log-")
    
    sm=StateMachine(solver=PrettySolver())
    
    #define the module/s to use in the search and all the database information here
    gf=GadgetFinder(imm, modules, dbname, dbtype, host, username, passwd)
    gf._debug=debug
    
    if debug:
        imm.log("[*] RAW Expression: %s"%str(exp))
    
    exp=parseExpression(exp, sm)
    
    if exp == None:
        imm.log("[!] Expression could not be parsed, please review it")
        return "Error, check usemode"
    
    imm.log("[*] Parsed Expression: %s"%str(exp))
    imm.log("[*] Stopping after %d results"%results_count)
    
    findings=[]
    
    #simulate a XCHG ESP, EXP/RETN
    sm.regs["ESP"]=exp
    sm.EIP=sm.readMemory(sm.regs["ESP"], 4)
    sm.regs["ESP"]+=4
    
    if debug:
        sm.simplify()
        sm.printState(imm)
    
    #first search by hashes
    imm.log("[*] Exact search (by hashes)")

    results = gf.searchByHashes(sm)
    
    if results:
        for info in results:
            imm.log("module_id=%d, module_base=0x%x, offset=0x%x, complexity=%d"%(info[0], gf.bases[info[0]], info[1], info[2]), gf.bases[info[0]]+info[1])
            findings.append(info)
            results_count-=1
            if not results_count:
                break
    
    if not results_count:
        return "Finished"
    
    #then by properties
    imm.log("[*] Heuristic search (by gadget's properties). Only new findings are showed.")
    tmp=sm.calcProperties()
    searchProps={}
    for k,v in tmp[0].iteritems():
        if v: searchProps[k]=v
    if tmp[1]:
        searchProps["FLAGS"]=(tmp[1], tmp[1]) #we only care about the flags that changed
    
    if debug:
        imm.log("Translated Properties:")
        mybin=lambda num: "".join([str((num >> y) & 1) for y in range(22-1, -1, -1)])
        for k,v in searchProps.iteritems():
            if k != "FLAGS":
                imm.log("%s:%s"%(k,mybin(v)))
            else:
                imm.log("%s: mask=0x%x, value=0x%x"%(k, v[0], v[1]))
    
    if searchProps:
        for info in gf.gdb.search_by_properties(searchProps, gf.propsDict):
            if info in findings:
                continue
            findings.append(info)
            gadget_sm=gf.gdb.get_gadget_by_offset(info[0], info[1])
            
            try:
                gEIP=gadget_sm.solver.exprString(gadget_sm.solver.simplify(gadget_sm.solver.extractExpr(gadget_sm.EIP, 0, 7)))
                tmp1=gadget_sm.memory.getIndexes(gEIP.replace("VAL","MEM"), recursive=False)
                parteip = sm.EIP[0:8]
                parteip.simplify()
                tmp2=sm.memory.getIndexes(str(parteip).replace("VAL","MEM"), recursive=False)
            except:
                continue
    
            if tmp1 != tmp2: #confirm EIP follows the wanted structure
                continue
            
            tmp1 = set(gadget_sm.solver.getVarDependency(gadget_sm.regs["ESP"], return_name=True))
            tmp2 = set(sm.solver.getVarDependency(sm.regs["ESP"], return_name=True))
            
            if tmp1 != tmp2: #confirm ESP follows the wanted structure
                continue
            
            imm.log("module_id=%d, module_base=0x%x, offset=0x%x, complexity=%d"%(info[0], gf.bases[info[0]], info[1], info[2]), gf.bases[info[0]]+info[1])
            results_count-=1
            if not results_count:
                break
    
    return "Finished"

def parseExpression(exp, sm):
    loc={}
    loc.update(sm.regs)
    loc.update(sm.flags)
    loc["EIP"]=sm.EIP
    loc["mem"]=lambda exp: sm.readMemory(exp, 4)

    try:
        return eval(exp, globals(), loc)
    except:
        return None
