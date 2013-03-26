"""
gadgets.py: started by modifying searchdep.py

Check out main for an example of how to use it
!gadgets as is will take a few minutes to run in ID
"""

import cPickle
import os

import operations

from immlib import *
from x86smt.sequenceanalyzer import SequenceAnalyzer
from deplib.libgadgets import searchOpcodesRETN

class Gadget:
    def __init__(self, addr, ins_cnt, byte_cnt):
        self.addr = addr
        self.ins_cnt = ins_cnt
        self.byte_cnt = byte_cnt
        self.sa = None
    
    def analyze(self, imm):
        self.sa = SequenceAnalyzer(imm)
        if not self.sa.analyze(self.addr, depth=self.ins_cnt, stopEIP=self.addr+self.byte_cnt):
            return False
        
        return True
        
def main(args):
    imm = Debugger()
    
    sear=searchOpcodesRETN(imm, filter_jumps=True, filter_calls=True)
    imm.markBegin()

    doProperties = False
    
    if len(args)<1:
        imm.log('Usage:')
        imm.log('!gadgets <dllname> [-p]')
        imm.log('-p pre-analyzes each gadget and stores some gadget properties')
        return 'See Log window for usage'
    
    if len(args)>1:
        doProperties = True
    
    mod=imm.findModuleByName(args[0])
    if not mod:
        imm.log("Module %s not found or name is ambiguous"%args[0])
        return "Module not found or ambiguous"

    uniq=mod.getName() + "_" + mod.getVersion().split("(")[0].strip()
    
    dump_name = uniq + '_gadgets.pkl'
    hash_name = uniq + '_hashes.pkl'
    if os.path.exists(dump_name):
        imm.log("%s exists. Overwriting..." % dump_name)
    if os.path.exists(hash_name):
        imm.log("%s exists. Overwriting..." % dump_name)

    dump_file = open(dump_name, 'wb')
    gadgets = set()
    gadget_cnt = 0
    hashes = {}
    
    for r in sear.search(args[0]):
        g = Gadget(r[0], r[1], r[2])
        
        if doProperties:
            if not g.analyze(imm):  #if the sequence analyzer failed, we cant use this gadget anyway
                imm.log("Sequence Analyzer failed for gadget 0x%x"%g.addr, g.addr)
                continue
            for k,v in g.sa.state.hashState().iteritems():
                key=(k,v)
                if not hashes.has_key(key):
                    hashes[key]=set()
                hashes[key].add(r[0])
        
        gadgets.add(g)
        gadget_cnt+=1
        
        imm.log('found gadget @ %s: %d instructions' % (hex(g.addr), g.ins_cnt), g.addr)

        if gadget_cnt % 200 == 0:
            cPickle.dump(gadgets, dump_file, cPickle.HIGHEST_PROTOCOL)
            if doProperties:
                for g in gadgets:
                    del g.sa
            del gadgets
            gadgets = set()
    
    if gadgets:
        cPickle.dump(gadgets, dump_file, cPickle.HIGHEST_PROTOCOL)
        if doProperties:
            for g in gadgets:
                del g.sa
        del gadgets
    dump_file.close()
    
    if hashes:
        hash_file = open(hash_name, 'wb')
        cPickle.dump(hashes, hash_file, cPickle.HIGHEST_PROTOCOL)
        hash_file.close()
    
    end = imm.markEnd()
    imm.log("Found %d gadgets in %f secs" % (gadget_cnt, end))
    imm.log("Gadgets saved to %s" % dump_name)
    if doProperties:
        imm.log("Gadget's hashes saved to %s" % hash_name)
    
    return 'Gadget search done. Found %d gadgets in %f seconds' \
        % (gadget_cnt, end)
