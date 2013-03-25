#/usr/bin/env python

import getopt
import struct
import immutils
from immlib import *

copyright="(C) Immunity, Inc."
DESC = "Dumps Acrobat Reader Cache state"

class AdobeHeap:
    def __init__(self,AcroPool):
        '''
        AcroManagingPool (hardcoded address depens on version of the AcroRd32.dll)
        From this address it's possible to access all managing structures of their custom heap implementation.
        '''
        self.AcroPool         = AcroPool
        self.imm              = Debugger()
        self.pAcroCacheList   = []
        self.CacheHeadersInfo = []
        self.AcroManagingPool()
        
    def AcroManagingPool(self):
        self.AcroPool        += 0xC                                            #Reserved           
        self.mem              = self.imm.readMemory(self.AcroPool,128)         #Managing structures for AcroCache
        self.lpCacheManaging  = struct.unpack("32L",self.mem)
        self.AcroPool        += (0x90 - 0xC)                                   #Header of the first AcroBlock
        self.FirstAcroBlock   = self.imm.readLong(self.AcroPool)
        
    def CacheManager(self,addr):
        self.AcroPool = self.imm.readMemory(addr,0x10)
        (pAcroPool,pFreeBlocksList,pAcroCacheList,blocksize) = struct.unpack("4L",self.AcroPool)
        self.imm.log("pAcroPool: 0x%08x pFreeBlocksList: 0x%08x pAcroCacheList: 0x%08x blocksize: 0x%08x" % (pAcroPool,pFreeBlocksList,pAcroCacheList,\
                                                                                                             blocksize), address = pAcroCacheList)
        return pAcroCacheList
    
    def CacheHeader(self,addr):
        self.AcroPool = self.imm.readMemory(addr,0x18)
        (pCacheManager,allocatedBlocks,flag,blink,flink,size) = struct.unpack("6L",self.AcroPool)
                      
        self.imm.log("CacheManager: 0x%08x AllocatedBlocks: 0x%08x Flags: 0x%08x BLINK: 0x%08x FLINK: 0x%08x Size: 0x%08x" % (pCacheManager,allocatedBlocks\
                                                                                                                              ,flag,blink,flink,size), address = addr)
        return flink

    def walkCache(self,addr):
        isAcroBlock = False
        isCache = False

        flag = self.imm.readLong(addr+0x8)
        if flag == 2:
            isAcroBlock = True
            size = self.imm.readLong(addr+0x18)
        elif flag == 0:
            isCache = True
            size = self.imm.readLong(addr+0x14)
            self.imm.log("")
            self.imm.log("***Walking through 0x%08x bytes cache***"%size)
        
        i = 0
        while 1:
            Flink = self.imm.readLong(addr+0x10)
            AllocatedBlocks = self.imm.readLong(addr+0x04)
            AcroBlockSize = self.imm.readLong(addr+0x14)
            if not Flink:
                self.imm.log("***Walk Done***")
                break 
            if isCache:
                self.imm.log("Cache[%d]: 0x%08x | Allocated Blocks: [%d/128]" % (i,addr,AllocatedBlocks), address = addr)
            elif isAcroBlock:
                self.imm.log("AcroBlock: 0x%08x | Size: 0x08%x" % (Flink,AcroBlockSize), address = Flink)
            addr = Flink
            i += 1           
        
    def getCacheManagers(self):
        self.imm.log("")
        self.imm.log("CacheManagers List:")
        i=0
        for x in self.lpCacheManaging:
            self.imm.log("lpCacheManaging[%d]: 0x%08x" % (i,x))
            i += 1
            
    def getCacheManagersInfo(self):
        self.imm.log("")
        self.imm.log("[Cache Managers Info]")
        for x in self.lpCacheManaging:
            self.pAcroCacheList.append(self.CacheManager(x))
                
    def getCacheHeaders(self):
        self.imm.log("")
        self.imm.log("[Cache Headers]")  
        for x in self.pAcroCacheList:
            try:
                self.CacheHeadersInfo.append(self.CacheHeader(x))
            except:
                pass        
         
    def dumpCache(self):
        self.getCacheManagers()
        self.getCacheManagersInfo()
        self.getCacheHeaders()
        self.pAcroCacheList.pop(0) #unused entry
        
        for x in self.pAcroCacheList:
            self.walkCache(x)
            
    def DumpAcroBlocks(self):
        addr = self.FirstAcroBlock
        self.AcroPool = self.imm.readMemory(addr,0x18)
        (pAcroPool,reserved,flag,blink,flink,size) = struct.unpack("6L",self.AcroPool)
        self.walkCache(flink)
    

def usage(imm):       
    imm.log("!acrocache")        
    imm.log("     -c                     Dump AcroCache state")        
    imm.log("     -f CACHEBLOCKADDR      Follow CacheBlocks of same size and show allocations count")
    imm.log("     -b                     Dump AcroBlocks")        

def main(args):
    imm = Debugger()    
    pAcroManagingPool = 0x014D38A0 #Acrobat Reader 9.4.0
    
    try:
        AcroManagingPool = imm.readLong(pAcroManagingPool)
    except:
        return "Couldn't read from AcroManagingPool pointer. Are you on Reader 9.4.0?"                    
    adobe = AdobeHeap(AcroManagingPool)    
    
    
    if not args:
        usage(imm)
    try:
        opts, argo = getopt.getopt(args, "bcf:")
    except getopt.GetoptError:
        usage(imm)
    for o,a in opts:
        if o == "-f":
            try:
                adobe.walkCache(int(a, 16))
            except ValueError, msg:
                return "Invalid address: %s" % a
        if o == "-b":
            adobe.DumpAcroBlocks()
        if o == "-c":
            adobe.dumpCache()
        
    return "done"
