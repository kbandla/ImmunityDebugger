class PathGenerator:

    def __init__(self, basic_blocks, bb_edges):
        self.basic_blocks = basic_blocks
        self.bb_edges = bb_edges
        self.path_addrs = set()
        
    def generatePaths(self, start_addr):
        if start_addr not in self.basic_blocks:
            raise Exception("Unknown address %s" % \
                            hex(start_addr))

        start_bb = self.basic_blocks[start_addr]
        
        if start_addr not in self.bb_edges:                
            p = Path(start_addr, self.basic_blocks, self.bb_edges)
            yield p
        else:
            self.path_addrs.add(start_addr)
            
            for next_bb_addr in self.bb_edges[start_addr]:
                if next_bb_addr in self.path_addrs:
                    p = Path(start_addr, self.basic_blocks,
                               self.bb_edges)
                    p.has_loop = True
                    yield p
                    continue
            
                for tail in self.generatePaths(next_bb_addr):
                    p = Path(start_addr, self.basic_blocks,
                             self.bb_edges)
                    p.extend(tail)
                    yield p

            self.path_addrs.remove(start_addr)
            
class Path:

    def __init__(self, start_addr, basic_blocks=None, edges=None):
        self.bb_addrs = [start_addr]
        self.basic_blocks = basic_blocks
        self.edges = edges
        self.has_loop = False

    def __len__(self):
        return len(self.bb_addrs)

    def __getitem__(self, bb_idx):
        addr = self.bb_addrs[bb_idx]
        return self.basic_blocks[addr]
    
    def __str__(self):
        if self.basic_blocks is None or self.edges is None:
            raise Exception("You must initialise the path object " + \
                            "with its correspnding basic block " + \
                            "graph info before use")
        
        tail_bb = self.basic_blocks[self.bb_addrs[-1]]
        tail_bb_end_addr = tail_bb.end_addr

        out = []
        [out.append(hex(addr)) for addr in self.bb_addrs]

        res = ""
        if self.has_loop:
            res = "(LOOP) %s" % (','.join(out))
        else:
            res = "%s" % (','.join(out))

        return res

    def getTailBb(self):
        addr =  self.bb_addrs[-1]
        return self.basic_blocks[addr]
    
    def extend(self, other):
        self.bb_addrs.extend(other.bb_addrs)
        self.has_loop = (self.has_loop or other.has_loop)

