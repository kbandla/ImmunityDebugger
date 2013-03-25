from immlib import *

class BasicBlock:

    def __init__(self, start_addr=None, start_op=None, end_addr=None,
        end_op=None):
        self.start_addr = start_addr
        self.end_addr = end_addr

        self.start_op = start_op
        self.end_op = end_op

class BasicBlockGraph:

    def __init__(self):
        # Dictionary of addresses to basic blocks        
        self.basic_blocks = {}
        # The outgoing edges for a basic block identified by its
        # starting address. A dictionary of addresses to a list of
        # addresses of basic blocks that the key address may branch to        
        self.bb_out_edges = {}
        # The incoming edges for a basic block identified by its
        # starting address. As above.        
        self.bb_in_edges = {}

    def log(self, imm):
        imm.log("** BASIC BLOCKS **")
        for bb_addr in self.basic_blocks:
            bb = self.basic_blocks[bb_addr]
            imm.log("BB start %s, end %s" % (hex(bb.start_addr),
                                             hex(bb.end_addr)),
                    bb.start_addr)

        imm.log("** FORWARD EDGES **")
        for bb_addr in self.bb_out_edges:
            out = []
            [out.append(hex(addr)) \
             for addr in self.bb_out_edges[bb_addr]]
            imm.log("%s -> %s" % (hex(bb_addr), ','.join(out)),
                         bb_addr)
    
        imm.log("** BACKWARD EDGES **")
        for bb_addr in self.bb_in_edges:
            out = []
            [out.append(hex(addr)) \
             for addr in self.bb_in_edges[bb_addr]]
            imm.log("%s -> %s" % (hex(bb_addr), ','.join(out)),
                         bb_addr)        
        
class CodeStructureAnalyzer:

    def __init__(self, imm, start_addr):
        self.imm = imm
        self.start_addr = start_addr

    def buildIncomingGraph(self, basic_blocks, out_graph):
        """
        This function takes a dictionary of basic blocks and a
        dictionary describing outgoing edges from the basic blocks
        and constructs a dictionary of the incoming edges to each
        basic block. 
        """

        bb_in_edges = {}
        
        for out_bb_addr in out_graph:
            for in_bb_addr in out_graph[out_bb_addr]:
                if in_bb_addr in bb_in_edges:
                    bb_in_edges[in_bb_addr].append(out_bb_addr)
                else:
                    bb_in_edges[in_bb_addr] = [out_bb_addr]

        return bb_in_edges
        
    def getBasicBlockGraph(self):
        work_list = []
        bb_out_edges = {}
        bb_in_edges = {}
        basic_blocks = {}

        next_addr = self.start_addr
        next_op = self.imm.disasm(next_addr, DISASM_FILE)
        next_op_type = next_op.getOpType()[0] & DEC_TYPEMASK

        curr_bb = BasicBlock(start_addr=next_addr, start_op=next_op)
        basic_blocks[next_addr] = curr_bb

        while True:
            if curr_bb.end_addr is not None:
                try:
                    curr_bb = work_list.pop()
                    prev_addr = curr_bb.start_addr

                    prev_op = curr_bb.start_op
                    next_addr = prev_addr
                except IndexError:
                    break
            else:
                prev_addr = next_addr
                prev_op = next_op
                
                next_addr = prev_addr + prev_op.getOpSize()

            next_op = self.imm.disasm(next_addr, DISASM_FILE)
            next_op_type = next_op.getOpType()[0] & DEC_TYPEMASK
            decode_info = Decode(next_addr)            

            if decode_info.isJmpDestination(next_addr) or \
               decode_info.isCallDestination(next_addr):

                if next_addr == curr_bb.start_addr:
                    continue
                
                curr_bb.end_addr = prev_addr
                curr_bb.end_op = prev_op
                
                if curr_bb.start_addr in bb_out_edges:
                    bb_out_edges[curr_bb.start_addr].append(next_addr)
                else:
                    bb_out_edges[curr_bb.start_addr] = [next_addr]
                    
                if not next_addr in basic_blocks:
                    new_bb = BasicBlock(start_addr=next_addr,
                                        start_op=next_op)
                    basic_blocks[next_addr] = new_bb
                    work_list.append(new_bb)                                
                continue

            if next_op.isJmp():
                curr_bb.end_addr = next_addr
                curr_bb.end_op = next_op
                jmp_target = next_op.getJmpAddr()
                
                if curr_bb.start_addr in bb_out_edges:
                    bb_out_edges[curr_bb.start_addr].append(jmp_target)
                else:
                    bb_out_edges[curr_bb.start_addr] = [jmp_target]

                if not jmp_target in basic_blocks:
                    jmp_op = self.imm.disasm(jmp_target, DISASM_FILE)
                    
                    new_bb = BasicBlock(start_addr=jmp_target,
                                        start_op=jmp_op)
                    basic_blocks[jmp_target] = new_bb
                    
                    work_list.append(new_bb)                    
                continue
            elif next_op.isConditionalJmp():
                curr_bb.end_addr = next_addr
                curr_bb.end_op = next_op

                jmp_target = next_op.getJmpAddr()
                if curr_bb.end_addr in bb_out_edges:
                    bb_out_edges[curr_bb.start_addr].append(jmp_target)
                else:
                    bb_out_edges[curr_bb.start_addr] = [jmp_target]
                    
                if not jmp_target in basic_blocks:
                    jmp_op = self.imm.disasm(jmp_target, DISASM_FILE)

                    new_bb = BasicBlock(start_addr=jmp_target,
                                        start_op=jmp_op)
                    basic_blocks[jmp_target] = new_bb          

                    work_list.append(new_bb)

                fall_thru_addr = next_addr + next_op.getSize()
                if curr_bb.start_addr in bb_out_edges:
                    bb_out_edges[curr_bb.start_addr].append(fall_thru_addr)
                else:
                    bb_out_edges[curr_bb.start_addr] = [fall_thru_addr]

                if not fall_thru_addr in basic_blocks:
                    fall_thru_op = self.imm.disasm(fall_thru_addr, DISASM_FILE)
                    
                    new_bb = BasicBlock(start_addr=fall_thru_addr,
                        start_op=fall_thru_op)
                    basic_blocks[fall_thru_addr] = new_bb            

                    work_list.append(new_bb)
                continue
            elif next_op.isRet():
                curr_bb.end_addr = next_addr
                curr_bb.end_op = next_op
                continue
        
        bb_in_edges = self.buildIncomingGraph(basic_blocks,
                                                bb_out_edges)
        
        bb_graph = BasicBlockGraph()
        bb_graph.basic_blocks = basic_blocks
        bb_graph.bb_out_edges = bb_out_edges
        bb_graph.bb_in_edges = bb_in_edges

        return bb_graph
