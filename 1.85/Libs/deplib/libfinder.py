from deplib.libgadgets import *

class GadgetFinder:
    def __init__(self, imm, modules=None, dbname=None, dbtype=None, host=None, username="", passwd=""):
        self.imm = imm
        self.gdb = GadgetsDB(imm, dbtype, dbname, host, username, passwd)
        
        if not modules:
            self.modules=self.gdb.get_all_module_ids()
        else:
            self.modules = self.gdb.get_module_ids(modules)
        
        self.bases = self.gdb.get_module_base_from_id(self.modules)
        self.hashesDict = HashesDictionary(self.gdb, self.modules)
        self.propsDict = PropertiesDictionary(self.gdb, self.modules)
        self._debug = False

    def allOK(self):
        if not self.gdb.db_connection:
            self.imm.log("[!] Could not connect to db, exiting...")
            return False
        
        if not self.modules:
            self.imm.log("[!] No valid module was found")
            return False
        
        return True
        
    def searchByProperties(self, regProps=None, regMemIndexes=None, flagProps=None):
        """
        regProps is a dictionary with registers as key and a list of regs or the word "FLAGS" or the word "CONST" for cases where it is modified only by a constant value.
        regMemIndexes is a dictionary with registers as key and a list of regs, the word "FLAGS" or the word "CONST" for independant constant indexes (this last one is exclusive)
        
        Note: any non-present register means it's not important for the search
        
        flagProps is a dictionary with flags as key (one letter for each flags, like in "CPAZSDO"), and as values one of this:
          - True: must be modified
          - False: must not be modified
          - None (or not present): we dont care about this flag
        
        ex: regProps={"ESP":"EAX"}, regMemIndexes={"EIP":"EAX"} can be used to find a stack-pivot from EAX.
        
        It returns an iterator over the results from the database.
        Each result is a 3-tuple: module_id, module_offset, gadget_complexity.
        """
        
        if not self.allOK():
            return
        
        if not regProps:
            regProps={}
        
        if regMemIndexes:
            for k,v in regMemIndexes.iteritems():
                if regProps.has_key(k):
                    regProps[k]=(regProps[k], v)
                else:
                    regProps[k]=((), v)

        props=self.gdb.translate_properties(regProps, flagProps)
        if self._debug:
            self.imm.log("Translated Properties:")
            mybin=lambda num: "".join([str((num >> y) & 1) for y in range(22-1, -1, -1)])
            for k,v in props.iteritems():
                if k != "FLAGS":
                    self.imm.log("%s:%s"%(k,mybin(v)))
                else:
                    self.imm.log("%s: mask=0x%x, value=0x%x"%(k, v[0], v[1]))
        
        return self.gdb.search_by_properties(props, self.propsDict)

    def searchByHashes(self, sm):
        """
        Search by retrieving the hashes of all modified mem/reg/flags of a StateMachine instance.
        
        It returns an iterator over the results from the database.
        Each result is a 3-tuple: module_id, module_offset, gadget_complexity.
        """
        
        if not self.allOK():
            return
        
        sm.simplify() #canonicalize state
        hashes=sm.hashState()
        if self._debug:
            self.imm.log("Hashes to look up:")
            for k,v in hashes.iteritems():
                self.imm.log("%s:0x%08x"%(k,v))
        
        return self.gdb.search_by_hashes(hashes, self.hashesDict)
