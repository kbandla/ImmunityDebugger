#!/usr/bin/env python

##Copyright IBM Corp. 2010
##
##Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at 
##
##http://www.apache.org/licenses/LICENSE-2.0 
##
##Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License. 

import immlib
import getopt
from libheap import *
import libdatatype

DESC= "Low Fragmentation Heap Viewer"
def usage(imm):
    imm.log("!horse  [-h HEAP_ADDR] [-b BLOCKS_ADDR] [-s Heap Bucket / SubSegment Info")
    imm.log("   -h  HEAPADDR    Set the heap address to inspect")
    imm.log("   -b  BLOCKSADDR  Set the _HEAP_LIST_LOOKUP block to inspect")
    imm.log("   -n  Find bins which are NOT being managed by the LFH")

def main(args):
    imm = immlib.Debugger()
    window = None

    if not args:
        imm.log("Please supply a valid _HEAP")  
        return "NO HEAP PASSED"

    # options:
    #   -h HEAP
    #   -b Only look at specific _HEAP_LIST_LOOKUP
    #   -n Look for empty bins
    try:
        opts, argo = getopt.getopt(args, "h:nsb:")
    except getopt.GetoptError:
        #imm.setStatusBar("Bad heap argument %s" % args[0])
        usage(imm)
        return "Bad heap argument %s" % args[0]
    
    heap = 0x0
    lfhthreshold = 0x12
    singleblock = False
    blockindex = 0x0
    emptybins = False
    restore = False
    opennewwindow = False

    for o,a in opts:
        if o == "-h":
            try:
                heap = int(a, 16)
            except ValueError, msg:
                return "Invalid heap address: %s" % a
        elif o == "-b":
            singleblock = True
            try:
                blockindex = int(a, 16)
            except ValueError, msg:
                return "Invalid heap address: %s" % a
        elif o == "-n":
            emptybins = True
        elif o == "-r":
            restore = True

    if (heap and ( heap in imm.getHeapsAddress() )) or blockindex:
        tag = "heap_%08x" % heap

        if not opennewwindow:            
            window = imm.getKnowledge(tag)
            if window and not window.isValidHandle():
                imm.forgetKnowledge(tag)
                del window
                window = None

        if not window:
            window = imm.createTable("Heap dump 0x%08x" % heap, ["Address", "Chunks"] )
            imm.addKnowledge(tag, window, force_add = 1)

        if not heap and blockindex:
            pheap = imm.getHeap(blockindex & 0xFFFF0000, restore)
        else:
            pheap = imm.getHeap( heap, restore )

        if pheap and pheap.FrontEndHeapType == 0x2 and pheap.FrontEndHeap:
            lfhthreshold = 0x11

        for i in (0, len(pheap.blocks)-1):
            block = pheap.blocks[i]

            #we're looking for a specific blockindex
            if singleblock:
                if block.address != blockindex:
                    continue
                
            num_of_freelists = block.ArraySize - block.BaseIndex
            window.Log("Printing Block information for 0x%08x" % block.address)
            window.Log("ExtendedLookup => 0x%08x" % block.ExtendedLookup)
            window.Log("ArraySize [max permitted in blocks] => 0x%08x" % block.ArraySize)
            window.Log("BaseIdex => 0x%08x" % block.BaseIndex)
            window.Log("End Block information for 0x%08x" % block.address)
            window.Log("Block has [0x%x] FreeLists starting at 0x%08x:"  % (num_of_freelists, block.ListHints))
            
            memory = imm.readMemory( block.ListHints, num_of_freelists * 8 )

            for a in range(0, num_of_freelists):
                free_entry = []
                # Previous and Next Chunk of the head of the double linked list
                (flink, heap_bucket) = struct.unpack("LL", memory[a *8 : a * 8 + 8] )

                bin = a + block.BaseIndex

                freelist_addr = block.ListHints + (bin - block.BaseIndex) * 8

                if heap_bucket != 0 and not emptybins:
                    if heap_bucket & 1:
                        window.Log("Flink => 0x%08x | Bin[0x%x] enabled | Bucket => 0x%08x" % (flink, bin, heap_bucket - 1), address = freelist_addr)
                    elif (heap_bucket & 0x0000FFFF) >= 0x22: #there appears to be a case where the LFH isn't activated when it should be...
                        window.Log("Flink => 0x%08x | Bin[0x%x] ??????? | Bucket => 0x%08x" % (flink, bin, heap_bucket), address = freelist_addr)
                    else:
                        allocations = heap_bucket & 0x0000FFFF
                        allocations = allocations / 2
                        amount_needed = lfhthreshold - allocations
                        window.Log("Flink => 0x%08x | Bin[0x%x] has had 0x%x allocations | Needs 0x%x more" % (flink, bin, allocations, amount_needed), address = freelist_addr)
                else:
                    if emptybins and heap_bucket == 0 and bin != 0x1 and bin != 0x0:
                        window.Log("Flink => 0x%08x | Bin[0x%x] is Emtpy!" % (flink, bin), address = freelist_addr)                    

            window.Log("")
        window.Log("=-" * 0x23 + "=")
        return "Heap 0x%x dumped" % heap 
    else:
        imm.log("Error: A proper heap or blockindex needs to be defined")
        return "Error: A proper heap or blockindex needs to be defined"
