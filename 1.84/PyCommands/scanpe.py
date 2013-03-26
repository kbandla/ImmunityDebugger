#!/usr/bin/env python

#-------------------------------------------------------------------------------
#
#    By BoB -> Team PEiD
#    http://www.SecretAsHell.com/BobSoft/
#    BobSoft@GMail.Com
#
#-------------------------------------------------------------------------------
#
#  Based on findpacker.py, this script will scan the entrypoint or whole file of
#   the main module, using Ero's PEFile and my UserDB.txt as before ..
#  Also added is logging of the entropy of the file and a guess based on the
#   entropy as to whether the file is packed or not.
#
#  By BoB, whilst freezing in England.. ;)
#  I only started with Python a week ago, and this is my first ever script ..
#  So, please excuse any bad Python coding :P
#
#  Thanks to JMS for checking my dodgy code .. :)
#
#-------------------------------------------------------------------------------


__VERSION__  = '1.00'
ProgName     = 'ScanPE'
ProgVers     = __VERSION__
DESC         = "Detect a Packer/Cryptor of Main Module, also scan just EntryPoint .."


import immlib
import math
import pefile
import peutils


#-------------------------------------------------------------------------------

def usage(imm):
    imm.log(" ")
    imm.log("%s v%s By BoB -> Team PEiD" % (ProgName, ProgVers), focus=1, highlight=1)
    imm.log("This script will scan the loaded module for any matching signatures in .\Data\UserDB.TXT ..")
    imm.log("Usage:")
    imm.log("  !%s [-h]" % ProgName.lower())
    imm.log(" ")
    imm.log("Options:")
    imm.log("      -h : Hardcore mode - Scan whole file .. (default is to scan just the Entrypoint)")
    imm.log(" ")
    return "See log window (Alt-L) for usage .. "


#-------------------------------------------------------------------------------
# RawToRva - Convert offset to Rva ..

def rawToRva(pe, Raw):
    sections = [s for s in pe.sections if s.contains_offset(Raw)]
    if sections:
        section = sections[0]
        return (Raw - section.PointerToRawData) + section.VirtualAddress
    else:
        return 0


#-------------------------------------------------------------------------------
# GetSectionInfo - Returns info about section as string ..

def getSectionInfo(pe, Va):
    sec = pe.get_section_by_rva(Va - pe.OPTIONAL_HEADER.ImageBase)
    if sec:
        # Get section number ..
        sn = 0
        for i in range(pe.FILE_HEADER.NumberOfSections):
            if pe.sections[i] == sec:
                sn = i + 1
                break
        # Get section name ..
        name = ""
        for j in range(7):
            # Only until first null ..
            if sec.Name[j] == chr(0):
                break
            name = "%s%s" % (name, sec.Name[j])
        # If name is not blank then set name string to ', "<name>"'' ..
        if name != "":
            name = ", \"%s\"" % name
        # Return section number and name (if exist) ..
        return " (section #%02d%s)" % (sn, name)
    return " (not in a section)"


#-------------------------------------------------------------------------------
# GetEntropy - Returns entropy of some data - Taken from Ero's PEFile.py ..

def getEntropy(data):
    """Calculate the entropy of a chunk of data."""

    if not data:
        return 0

    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x)))/len(data)
        if p_x > 0:
          entropy += - p_x*math.log(p_x, 2)

    return entropy


#-------------------------------------------------------------------------------

def main(args):
    imm = immlib.Debugger()
    name = imm.getDebuggedName()

    EP_Only = 1
    if args:
        if args[0].lower() == '-h':
            EP_Only = 0
    try:
        Mod  = imm.getModule(name)
        if not Mod:
            raise Exception, "Couldn't find %s .." % name
    except Exception, msg:
        return "Error: %s" % msg

    imm.log(" ")
    imm.log("%s v%s By BoB -> Team PEiD" % (ProgName, ProgVers), focus=1, highlight=1)
    imm.log("Processing \"%s\" .." % name)

    # Load PE File ..
    pe = pefile.PE(name = Mod.getPath())

    # Displays same guessed results as PEiD -> Extra information -> Entropy ..
    e = getEntropy( pe.__data__ )
    if e < 6.0:
        a = "Not packed"
    elif e < 7.0:
        a = "Maybe packed"
    else:  # 7.0 .. 8.0
        a = "Packed"

    # Start processing ..
    imm.log("  o File Entropy : %.2f (%s)" % (e, a))
    imm.log("  o Loading signatures ..")
    imm.setStatusBar("Loading signatures ..")
    # Show now as sigs take a few seconds to load ..
    imm.updateLog()

    # Load signatures ..
    sig_db = peutils.SignatureDatabase('Data/UserDB.TXT')
    imm.log("  o %d total sigs in database .." % (sig_db.signature_count_eponly_true + sig_db.signature_count_eponly_false + sig_db.signature_count_section_start))
    # Display number of signatures to scan ..
    if EP_Only == 1:
        imm.log("  o %d EntryPoint sigs to scan .." % sig_db.signature_count_eponly_true)
        imm.log("  o Scanning Entrypoint ..")
        imm.setStatusBar("Scanning Entrypoint ..")
    else:
        imm.log("  o %d sigs to scan in hardcore mode .." % sig_db.signature_count_eponly_false)
        imm.log("  o Scanning whole file ..")
        imm.setStatusBar("Scanning whole file ..  This may take a few minutes, so go make a coffee ..")
    imm.log(" ")
    # Force update now or user will not know any info until scan finished ..
    # Which can take minutes for a large file scanned with -a option ..
    imm.updateLog()

    # Do the scan, EP only or hardcore mode ..
    ret = sig_db.match( pe, EP_Only == 1 )

    # Display results of scan ..
    imm.log("Result:")
    if not ret:
        imm.log("  Nothing found ..")
        imm.log(" ")
        return "Nothing found .."

    if EP_Only == 1:
        # If EP detection then result is a string and we know EP address ..
        va = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        addr = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        imm.log("  Found \"%s\" at offset 0x%08X %s" % (ret[0], addr, getSectionInfo(pe, va)), address = va)
        imm.log(" ")
        return "Found \"%s\" at 0x%08X .." % (ret[0], va)
    else:
        # If more than 1 returned detection, then display all possibilities ..
        if len(ret) > 1:
            a = 1
            for (addr, name) in ret:
                va = pe.OPTIONAL_HEADER.ImageBase + rawToRva(pe, addr)
                imm.log('  %02d : \"%s\" at offset 0x%08X %s' % (a, name[0], addr, getSectionInfo(pe, va)), address = va)
                a += 1
            imm.log(" ")
            return "Found %d possible matches .." % len(ret)
        else:
            # If only 1 detection then display result ..
            for (addr, name) in ret:
                va = pe.OPTIONAL_HEADER.ImageBase + rawToRva(pe, addr)
                imm.log('  Found \"%s\" at offset 0x%08X %s' % (name[0], addr, getSectionInfo(pe, va)), address = va)
                imm.log(" ")
                return "Found \"%s\" at 0x%08X .." % (name[0], va)

