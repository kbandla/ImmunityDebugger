import operations

from libanalyze import DISASM_FILE
from bugchecker import MAX_INT_32, BugChecker, BugCheckResults

class IntOverflowChecker(BugChecker):
    def checkIns(self, sa, ins):
        res = None
        status = False
        op = operations.operation(ins)
        disasm_str = op.removeLockPrefix()
        solver = sa.state.solver
        
        if self.debug:
            self.imm.log("check_ins (%s): %s" % \
                            (hex(ins.getAddress()), disasm_str),
                            ins.getAddress())
        
        if disasm_str == "ADD":
            dst = sa.buildState(ins.operand[0])
            src = sa.buildState(ins.operand[1])
            
            dst_val = sa.getValueFromState(dst)
            src_val = sa.getValueFromState(src)

            res_64 = solver.addExpr(dst_val, src_val, 64)

            # Check if the result temporarily saved as 64 bit int is 
            # greater than 2**32-1
            gt_expr = solver.gtExpr(res_64, solver.constExpr(MAX_INT_32))
            status = solver.checkSat(gt_expr)
        elif disasm_str == "ADC":
            pass
        elif disasm_str == "SUB":
            pass
        elif disasm_str == "INC":
            pass
        elif disasm_str == "DEC":
            pass
        elif disasm_str == "MUL":
            pass
        elif disasm_str == "LEA":
            pass
        
        if status:
            if self.debug:
                self.imm.log("check_ins (%s): Bug found" % \
                             hex(ins.getAddress()))
            res = BugCheckResults(ins.getAddress(),
                                  solver.getConcreteModel())
        return res
