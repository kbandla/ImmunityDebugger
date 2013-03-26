#!/usr/bin/env python

#-------------------------------------------------------------------------------
#
#    By BoB -> Team PEiD
#    http://www.SecretAsHell.com/BobSoft/
#    BobSoft@GMail.Com
#
#-------------------------------------------------------------------------------
#
#  Thanks to JMS for some TLS code used in this script .. ;)
#
#-------------------------------------------------------------------------------
#
#  V1.01
#    Fixed a missing var in getAddressInTlsCallbacks() ..
#
#-------------------------------------------------------------------------------

import immlib
import pefile

__VERSION__ = '1.01'
DESC        = "Sets a breakpoint on entrypoint of main module .."
ProgName    = 'BpxEP'
ProgVers    = __VERSION__


#-------------------------------------------------------------------------------

def usage(imm):
    imm.Log(" ")
    imm.Log("%s v%s By BoB -> Team PEiD" % (ProgName, ProgVers),focus=1, highlight=1)
    imm.Log("Description:")
    imm.Log("  Sets Breakpoint on entrypoint of main module and optionally runs until entrypoint reached ..")
    imm.Log("  For use when a packed file fails to stop at entrypoint, EG [MSLRH], UPack ..")
    imm.Log("  Debugging these files results in ImmDbg starting at system startup breakpoint ..")
    imm.Log("  Also there is ability to place breakpoint at TLS callbacks, this is for packers that")
    imm.Log("   run code from TLS callbacks, or unpack from TLS, EG: ASDPack v1.0 ..")
    imm.Log("  With ASDPack the target PE File loaded into ImmDbg will run instead of stopping, so ")
    imm.Log("   you must set Debugging Options -> Event -> Start at system breakpoint - then run script")
    imm.Log("   with -tls and -go params.. ")
    imm.Log(" ")
    imm.Log("Usage:")
    imm.Log("  !%s [-go] [-tls]" % ProgName.lower())
    imm.Log(" ")
    imm.Log("Options:")
    imm.Log("   -go : After setting breakpoint on EP, run (F9)")
    imm.Log("  -tls : Set Bpx on TLS callbacks too .. (Uses code by JMS)")
    imm.Log(" ")
    return "See log window (Alt-L) for usage .. "


#-------------------------------------------------------------------------------
# Some of this TLS code from JMS, thanks :)
# Returns 0 if no callbacks, else address of first callback ..

def hasTlsCallbacks(pe, imm):
    addr = 0
    # Maybe no TLS table ?
    if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
        tls_callbacks_table = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
        # Maybe no TLS callbacks pointer?
        if tls_callbacks_table:
            addr = imm.readLong(tls_callbacks_table)
            # Maybe has TLS table, has Callbacks pointer, but points to null ..  (Delphi does this)
            if addr != 0:
                return tls_callbacks_table
    return addr


#-------------------------------------------------------------------------------
# Returns fixed callback address if imagebase changed ..

def getAddressInTlsCallbacks(pe, imm, index):
    # This was missing in v.00 .. ;/
    addr = 0
    a = hasTlsCallbacks(pe, imm)
    if a != 0:
        addr = imm.readLong(a + (index * 4))  # Zero-Based index !
        # Maybe relocated ?
        if imm.getModule(imm.getDebuggedName()).getBaseAddress() != pe.OPTIONAL_HEADER.ImageBase:
            # Fix the TLS Callback Virtual Address ..
            addr = (addr - pe.OPTIONAL_HEADER.ImageBase) + imm.getModule(imm.getDebuggedName()).getBaseAddress()
    return addr


#-------------------------------------------------------------------------------

def isAddressInTlsCallbacks(pe, imm, addr):
    for i in range(1000):
        TlsAddr = getAddressInTlsCallbacks(pe, imm, i)
        if TlsAddr == addr:
            return True
        if TlsAddr == 0:
            return False


#-------------------------------------------------------------------------------

def main(args):
    imm = immlib.Debugger()
    Mod = imm.getModule(imm.getDebuggedName())
    pe = pefile.PE(name=Mod.getPath())
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint + Mod.getBaseAddress()
    imm.Log(" ")
    imm.Log("%s v%s By BoB -> Team PEiD" % (ProgName, ProgVers), highlight=1)

    TlsBpx   = False
    RunAfter = False
    if args:
        for i in range(len(args)):
            if (args[i].lower() == "-tls"):
                TlsBpx = not TlsBpx
            if (args[i].lower() == "-go"):
                RunAfter = not RunAfter

    if TlsBpx == True:
        # Do we have a Tls table and callbacks ?
        addr = getAddressInTlsCallbacks(pe, imm, 0)
        if (addr == 0):
            # Stop and display error, else we could be running with -go .. :/
            imm.Log("This file has no TLS callbacks ..")
            imm.Log(" ")
            return "There were errors, please see log window (Alt-L)"

        count = 0
        while addr != 0:
            imm.setTemporaryBreakpoint(addr)
            count += 1
            imm.Log("Set Breakpoint on TLS callback #%d .." % count, address=addr)
            imm.setComment(addr, "TLS callback #%d" % count)
            addr = getAddressInTlsCallbacks(pe, imm, count)

    # Get current EIP in ImmDbg ..
    EIP = imm.getCurrentAddress()
    # User error check .. :)
    if EIP != ep:
        imm.setTemporaryBreakpoint(ep)
        imm.Log("Breakpoint set at EntryPoint ..", address=ep)
        imm.setComment(ep, "EntryPoint of \"%s\" .. " % imm.getDebuggedName())
        # Only run if not at EP .. :)
        if RunAfter == True:
            imm.Log("Running ..")
            imm.Run()
    else:
        imm.Log("You are already at entrypoint ..")
        imm.Log(" ")
        return "Program entry point"

    imm.Log(" ")

    EIP = imm.getCurrentAddress()
    # If we ran then we should be at EP ..
    if EIP == ep:
        if imm.isAnalysed(ep) == 0:
            # Try to analyse code at entrypoint ..
            imm.analyseCode(ep)
        return "Program entry point"

    # Maybe we have hit a TLS Callback ?
    elif isAddressInTlsCallbacks(pe, imm, EIP):
        if imm.isAnalysed(EIP) == 0:
            # Try to analyse code at callback entrypoint ..
            imm.analyseCode(EIP)
        return imm.getComment(EIP)

    else:
        return "Breakpoint set at EntryPoint of \"%s\" .." % imm.getDebuggedName()

