from sequenceanalyzer import SequenceAnalyzer

class UnsatPathConditionException(Exception):
    pass

class NoFollowSequenceAnalyzer(SequenceAnalyzer):
    def __init__(self, imm, analysis_mods=[]):
        SequenceAnalyzer.__init__(self, imm, analysis_mods=analysis_mods)
        
        # Either of these should be set if only one direction of a
        # conditional jmp instruction should be analysed
        self.check_jcc_taken = True
        self.check_jcc_not_taken = False
        
    def analyzeJMP(self, op):
        return
    
    def analyzeCALL(self, op):
        return
    
    def analyzeJcc(self, condition, finaladdress):
        """
        Analyze conditional jumps without following them.
        Used in replacement of 'analyzeJcc' by some tools like pathogen.py.
        
            @condition: generaly a flag (ie. OF for jo).
            @finaladdress: destination address (unused here).
        """
        
        if self.check_jcc_taken:
            # Check if the jcc can be taken
            self.state.solver.push()
            ret = self.state.solver.checkUnsat(condition)
            self.state.solver.pop()

            # Save the result of the last solve to query it later.
            if not ret:
                self.jcc_taken = True
            else:
                self.jcc_taken = False
                
            # Assert the condition as true and set everything for analysis.
            # This saves the condition for future usage.
            self.jcc_taken_condition = condition

        if self.check_jcc_not_taken:
            # Check if the fall-through is possible
            self.state.solver.push()
            not_cond = self.state.solver.boolNotExpr(condition)
            ret = self.state.solver.checkUnsat(not_cond)
            self.state.solver.pop()

            if not ret:
                self.jcc_not_taken = True
            else:
                self.jcc_not_taken = False

            self.jcc_not_taken_condition = not_cond
        
    def assert_jcc_taken(self, jmp_target, jmp_addr):
        """
        Create the assumption that the last jmpcc analyzed is taken.
        This modifies the state of the solver.
        """
        self.state.solver.assertFormula(self.jcc_taken_condition)
        
    def assert_jcc_not_taken(self):
        """
        Create the assumption that the last jmpcc analyzed is NOT taken.
        This modifies the state of the solver.
        """
        self.state.solver.assertFormula(self.jcc_not_taken_condition)
        

class PathWalker:

    """
    A path walker that uses the SequenceAnalyzer to determine
    feasible paths.
    """
    
    def __init__(self, imm, debug=False):
        self.imm = imm
        self.debug = debug
        self.sa = None

    def getAnalysisResults(self, checker=None):
        if self.sa is None:
            raise Exception("You must use walk to perform analysis first")
        
        return self.sa.getAnalysisResults(checker)
    
    def walk(self, path, analysis_mods=[]):
        tail_bb = path.getTailBb()
        tail_bb_end_addr = tail_bb.end_addr

        self.sa = NoFollowSequenceAnalyzer(self.imm, analysis_mods=analysis_mods)
        self.sa._debug = self.debug
        
        addr_idx = 0        
        while addr_idx < len(path) - 1:
            bb = path[addr_idx]
            addr = bb.start_addr
                
            next_bb = path[addr_idx + 1]
            next_addr = next_bb.start_addr

            if self.debug:
                self.imm.log("ANALYZE BB %s" % hex(bb.start_addr))
                
            if bb.end_op.isConditionalJmp() and \
               bb.end_op.getJmpAddr() == next_addr:
                self.sa.check_jcc_taken = True
                self.sa.check_jcc_not_taken = False
            elif bb.end_op.isConditionalJmp():
                self.sa.check_jcc_not_taken = True
                self.sa.check_jcc_taken = False

            self.sa.analyze(initialaddress=bb.start_addr,
                       stopEIP=bb.end_addr)
            
            if bb.end_op.isConditionalJmp():
                end_str = hex(bb.end_addr)
                next_str = hex(next_addr)
                
                if bb.end_op.getJmpAddr() == next_addr:
                    if self.sa.jcc_taken:
                        if self.debug:
                            self.imm.log("Valid transition from %s to %s" % \
                                (end_str, next_str), bb.end_addr)
                        self.sa.assert_jcc_taken(bb.end_op.getJmpAddr(),
                                           bb.end_addr)                       
                    else:
                        msg = "Infeasible path transition from %s to %s" % \
                            (end_str, next_str)
                        raise UnsatPathConditionException(msg)
                else:
                    if self.sa.jcc_not_taken:
                        if self.debug:
                            self.imm.log("Valid transition from %s to %s" % \
                                (end_str, next_str), bb.end_addr)
                        self.sa.assert_jcc_not_taken()
                    else:
                        msg = "Infeasible path transition from %s to %s" % \
                            (end_str, next_str)
                        raise UnsatPathConditionException(msg)
                    
            self.sa.state.EIP = self.sa.state.solver.lookupVar("EIP")[0]                                    
            addr_idx += 1

        # The final basic block isn't checked within the above loop
        self.sa.analyze(initialaddress=path[-1].start_addr,
                   stopEIP=path[-1].start_addr)
