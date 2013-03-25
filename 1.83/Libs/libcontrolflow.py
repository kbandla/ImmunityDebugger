#!/usr/bin/env python

"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}


"""

__VERSION__ = '1.0'

#############################################################################
class DominatorTree:
    def __init__(self, imm, addr, blocks = False, recursion = False):
        """
        This class takes a function start address and calculate all Dominator Tree related tables:
        - Predecessors
        - Iterated Predecessors
        - Dominators
        - Immediate Dominators
        - Post Dominators
        - Immediate Post Dominators

        @type  imm: Debbuger OBJECT
        @param imm: Debbuger

        @type  addr: DWORD
        @param addr: function start address

        @type  blocks: DICTIONARY|False
        @param blocks: Optionally you can provide a dictionary with the node address as key and a list of edges (mainly for testing purposes).
        """
        
        self.address = addr
        self.imm = imm
        self.blocks = {}
        self.predecessors = {}
        self.iterativepredecessors = {}
        self.dominators = {}
        self.immediatedominators = {}
        self.postdominators = {}
        self.immediatepostdominators = {}
        
        if blocks:
            self.blocks = blocks
        else:
            self.Initializate()
        
        self.CalculatePredecessors()
        self.CalculateDominators()
        self.CalculateImmediateDominators()
        if not recursion:
            self.CalculatePostAndImmediatePostDominators()
            self.CalculateIterativePredecessors()

    def Initializate(self):
        func = self.imm.getFunction(self.address)
        blocks = func.getBasicBlocks()
        
        for block in blocks:
            edges = block.getEdges()
            start = block.getStart()
            self.blocks[start] = edges
        
    
    def CalculatePredecessors(self):
        for start,edges in self.blocks.iteritems():
            #support an unknown quantity of edges (for inverse CFG processing)
            for edge in edges:
                if edge:
                    if edge not in self.predecessors.keys():
                        self.predecessors[edge] = []
                    self.predecessors[edge].append(start)
    
    def CalculateIterativePredecessors(self):
        for start in self.blocks:
            self.iterativepredecessors[start] = []
            if start in self.predecessors.keys():
                self.__iterative_predecessors_helper(start, start)
        
    def __iterative_predecessors_helper(self, base, newbase):
        for pred in self.predecessors[newbase]:
            if pred:
                if newbase in self.dominators[pred]:
                    #this is a loop
                    continue
                if pred not in self.iterativepredecessors[base]:
                    self.iterativepredecessors[base].append(pred)
                if pred in self.predecessors.keys():
                    self.__iterative_predecessors_helper(base, pred)
        
    def CalculateDominators(self):
        """ 
        Based in algorithm from "Advanced COMPILER DESIGN IMPLEMENTATION"
        """
        
        start = self.address
        change = True
        Domin = {}
        Domin[start] = [ start ]
        for n in self.blocks:
            if n != start:
                if n in self.predecessors.keys():
                    Domin[n] = self.blocks.keys()
                else:
                    #a node without predecessors it's just dead code
                    Domin[n] = [ n ]

        for n in Domin:
            tmp = Domin[n]
            tmp.sort()
            Domin[n] = tmp

        while change:
            change = False
            for n in self.blocks:
                if n != start and n in self.predecessors.keys():
                    T = self.blocks.keys()
                    for p in self.predecessors[n]:
                        #intersect Domin(p) with tmp
                        intersect = []
                        for d in Domin[p]:
                            if d in T and d not in intersect:
                                intersect.append(d)
                        T = intersect

                    #D = T U n
                    D = intersect
                    if n not in D:
                        D.append(n)
                    
                    D.sort()
                    if D != Domin[n]:
                        change = True
                        Domin[n] = D
        
        self.dominators = Domin

    def CalculateImmediateDominators(self):
        for node in self.blocks:
            idom = self.dominators[node][:]
            #idom(node) != node
            idom.remove(node)
            for dom in self.dominators[node]:
                if dom != node:
                    for sec_dom in self.dominators[dom]:
                        if sec_dom != dom and sec_dom in idom:
                            idom.remove(sec_dom)
            self.immediatedominators[node] = idom
    
    def CalculatePostAndImmediatePostDominators(self):
        invertedCFG = self.predecessors
        invertedCFG[self.address] = [ 0 ]
        
        newstart = invertedCFG.keys()
        for edges in invertedCFG.values():
            for edge in edges:
                if edge in newstart:
                    newstart.remove(edge)

        for onestart in newstart:
            dom = DominatorTree(self.imm, onestart, blocks=invertedCFG, recursion=True)
            self.postdominators[onestart]=dom.dominators
            self.immediatepostdominators[onestart]=dom.immediatedominators

    def getDominators(self):
        return self.dominators

    def getImmediateDominators(self):
        return self.immediatedominators

    def getPostDominators(self):
        return self.postdominators

    def getImmediatePostDominators(self):
        return self.immediatepostdominators

    def getPredecessors(self):
        return self.predecessors

    def getIteratedPredecessors(self):
        return self.iterativepredecessors

    def getControlFlowGraph(self):
        return self.blocks


class ControlFlowAnalysis:
    def __init__(self, imm, address, domtree=False):
        """
        @type  imm: Debbuger OBJECT
        @param imm: Debbuger

        @type  address: DWORD
        @param address: function start address

        @type  domtree: OBJECT|False
        @param domtree: Optionally you can provide a DominatorTree instance (mainly for testing purposes).
        """
        
        self.imm = imm
        self.address = address
        self.loops = []
        
        if domtree:
            self.domtree = domtree
        else:
            self.domtree = DominatorTree(self.imm, self.address)
    
    def findNaturalLoops(self):
        """
        This function finds Natural Loops inside a function, using the information provided by dominator tree class.
        
        @rtype: LIST
        @return: A list of loops, each with this structure:
          [ start, end, nodes ]
          start: address of node receiving the back edge
          end: address of node which has the back edge
          node: list of node's addresses involved in this loop
        """
        
        for start,edges in self.domtree.blocks.items():
            for edge in edges:
                if edge and edge in self.domtree.dominators[start]:
                    loopNodes = []
                    for pred in self.domtree.iterativepredecessors[start]:
                        if pred not in self.domtree.iterativepredecessors[edge]:
                            loopNodes.append(pred)
                    loopNodes.append(start)
                    self.loops.append([edge,start,loopNodes])
        
        return self.loops


