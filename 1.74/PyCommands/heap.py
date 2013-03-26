#!/usr/bin/env python

"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}
"""

import immlib
import getopt
from libheap import *
import libdatatype

DESC= "Immunity Heap Dump"
def usage(imm):
    imm.log("!heap  Heap dump of currents heaps")
    imm.log("!heap  [-h HEAP_ADDR] [-s] [-r] [-f] [-c]")
    imm.log("   -h  HEAPADDR    Set the heap address to inspect")
    imm.log("   -a  CHUNKADDR   Set the begging of a chunk to partially inspect")
    imm.log("   -s              Save heap's state")
    imm.log("   -r              Dump heap using restored value (in case of a broken chunk)")
    imm.log("   -f              Inspect the FreeList only")
    imm.log("   -c              Inspect the chunks only")
    imm.log("   -k              Shows the first 16 bytes of a chunk")
    imm.log("   -d              Inspect data on Chunks")
    imm.log("   -q              Dont show FreeList information")    
    imm.log("   -l              Inspect all the Low Fragmentation Information")
    imm.log("   -t  PACK_SIZE   Filter by Packed Size ( Real Size / 8 )")
    imm.log("   -u              Inspect LFH UserBlocks")
    imm.log("   -z              Inspect LFH Chunks", focus = 1 )

def main(args):
    imm = immlib.Debugger()
    window = None

    if not args:
        imm.log("### Immunity's Heapdump ###")  
        for hndx in imm.getHeapsAddress():
            imm.log("Heap: 0x%08x" % hndx, address = hndx, focus = 1)
        return "Heap command successful"

    # options:
    #   -h HEAP
    #   -s (save heap's state)
    #   -r (restore in case of broken heap)
    #   -f dump just the freelist
    #   -c dump just chunks
    #   -d discover
    try:
        opts, argo = getopt.getopt(args, "h:lsurfcqknzda:t:")
    except getopt.GetoptError:
        #imm.setStatusBar("Bad heap argument %s" % args[0])
        usage(imm)
        return "Bad heap argument %s" % args[0]
    heap = 0x0
    save = False
    restore = False
    freelist = False
    chunksflags = False
    chunkdisplay = 0
    opennewwindow = False
    discover = None
    chunkaddress = None
    LFH = False
    userblock = False
    lfhchunk = False
    showf = True
    fsize = -1

    for o,a in opts:
        if o == "-h":
            try:
                heap = int(a, 16)
            except ValueError, msg:
                return "Invalid heap address: %s" % a
        if o == "-a":
            try:
                chunkaddress = int(a, 16)
            except ValueError, msg:
                return "Invalid chunk address: %s" % a
        if o == "-t":
            try:
                fsize = int(a, 16)
            except ValueError, msg:
                return "Incorrect filter size : %s" % a

        elif o == "-s":
            save = True
        elif o == "-r":
            restore = True
        elif o == "-f":
            freelist = True
        elif o == "-c":
            chunksflags = True
        elif o == "-k":
            chunkdisplay = SHOWCHUNK_FULL
        elif o == "-n":
            opennewwindow = True
        elif o == "-d":
            discover = libdatatype.DataTypes(imm)
        elif o == '-l':
            LFH = True		
        elif o == '-u':	
            userblock = True		
        elif o == '-z':
            lfhchunk = True
        elif o == '-q':
            showf = False

    if heap and ( heap in imm.getHeapsAddress() ):
        tag = "heap_%08x" % heap

        if not opennewwindow:            
            window = imm.getKnowledge(tag)
            if window and not window.isValidHandle():
                imm.forgetKnowledge(tag)
                del window
                window = None

        if not window:
            imm.log( "%s %s " % (str(type(tag)), str(type(heap))) )
            window = imm.createTable("Heap dump 0x%08x" % heap, ["Address", "Chunks"] )
            imm.addKnowledge(tag, window, force_add = 1)

        # in case none of them are select, dump *
        if showf and (not chunksflags and not freelist):
            chunksflags = True
            freelist = True

        pheap = imm.getHeap( heap, restore )
        if save:
            imm.addKnowledge("saved_heap_%08x" % pheap.address , pheap, force_add = 1)

        window.Log("### Immunity's Heapdump ###")  
        window.Log("Dumping heap:    0x%08x" % heap, address = heap, focus = 1 )
        window.Log("Flags:           0x%08x Forceflags:             0x%08x" % (pheap.Flags, pheap.ForceFlags), address = heap)
        window.Log("Total Free Size: 0x%08x VirtualMemoryThreshold: 0x%08x" % (pheap.TotalFreeSize, pheap.VirtualMemoryThreshold), address = heap)
        if showf:
            for a in range(0, len(pheap.Segments)):
                if not pheap.Segments[a]:
                    break
                window.Log("Segment[%d]: 0x%08x" % (a, pheap.Segments[a].BaseAddress) ) 

        if freelist:
            if pheap.HeapCache:
                pheap.printHeapCache(uselog = window.Log)
            if hasattr(pheap, 'FreeListInUseLong'):
                pheap.printFreeListInUse(uselog = window.Log )
                
            pheap.printFreeList( uselog = window.Log)
        if hasattr(pheap, "Lookaside"):
            if pheap.Lookaside:
                pheap.printLookaside( uselog = window.Log )
                
        if chunksflags:
            for chunk in pheap.chunks:
                chunk.printchunk(uselog = window.Log, option = chunkdisplay, dt = discover)
        if userblock or lfhchunk:
            LFH = True

        if LFH and pheap.LFH:
            if not userblock and not lfhchunk:
                userblock = True
                lfhchunk = True
            window.Log("~" * 0x47)
            if pheap.LFH.LocalData:
                for seginfo in pheap.LFH.LocalData.SegmentInfo:
                    subseg_list = seginfo.SubSegment	
                    for subseg in subseg_list:
                        if fsize == -1 or subseg.BlockSize == fsize:
                            if userblock:				
                                window.Log("UserBlock size: 0x%04x %-8s: 0x%08x offset: %08x Depth: %x (0x%08x)" % (subseg.BlockSize, subseg.type, subseg.UserBlocks, subseg.Offset, subseg.Depth,  subseg.Next), address = subseg.UserBlocks)
                            if lfhchunk:			    
                                for chk in subseg.chunks:
                                    chk.printchunk(uselog = window.Log, option = chunkdisplay, dt = discover)

        window.Log("=-" * 0x23 + "=")
        return "Heap 0x%x dumped" % heap 

    elif chunkaddress:

        tag = "chunks_%08x" % chunkaddress

        if not opennewwindow:            
            window = imm.getKnowledge(tag)

        if not window:
            window = imm.createTable("Heap dump 0x%08x" % chunkaddress, ["Address", "Chunks"] )
            imm.addKnowledge(tag, window, force_add = 1)

        pheap = PHeap( imm )

        window.Log("### Immunity's Heapdump ###")  
        window.Log("Dumping Chunks from address:    0x%08x" % chunkaddress, address = chunkaddress, focus = 1 )

        for chunk in pheap.getChunks( chunkaddress ):
            chunk.printchunk(uselog = window.Log, option = chunkdisplay, dt = discover)

        window.Log("=-" * 0x23 + "=")
        return "Heap 0x%x dumped" % heap    
    else:
        imm.log("Error: A proper heap needs to be defined")
        return "Error: A proper heap needs to be defined"
