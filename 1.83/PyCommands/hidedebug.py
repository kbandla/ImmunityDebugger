#!/usr/bin/env python

#-------------------------------------------------------------------------------
#
#    By BoB -> Team PEiD
#    http://www.PEiD.info/BobSoft/
#    BobSoft@GMail.Com
#
#-------------------------------------------------------------------------------

import immlib
import getopt
import random
import ctypes

#-------------------------------------------------------------------------------

__VERSION__ = '1.00'
ProgName    = 'HideDebug'
ProgVers    = __VERSION__
DESC        = "Patches lots of anti-debug protection ..  (try \"!usage %s\" for details)" % ProgName.lower()

#-------------------------------------------------------------------------------

Docs = """

Loosely based on patch.py (c) Immunity inc ..  :)

Patches:
    o IsDebuggerPresent           (With Poly-patch code, as too easy to detect Xor EAX, EAX)
    o ZwQueryInformationProcess
    o CheckRemoteDebuggerPresent
    o PEB.IsDebugged
    o PEB.ProcessHeap.Flag
    o PEB.NtGlobalFlag
    o PEB.Ldr 0xFEEEFEEE filling
    o GetTickCount                (With poly-patch code, as too easy to detect Mov EAX, xxxxxxxx)
    o ZwQuerySystemInformation    (Used by CreateToolHelp32Snapshot / Process32First / Process32Next and others)
    o FindWindowA
    o FindWindowW
    o FindWindowExA
    o FindWindowExW
    o EnumWindows

    
Types:
    o Anti-Debug Types:
        IsDebuggerPresent
        ZwQueryInformationProcess
        CheckRemoteDebuggerPresent
        PEB                         (All PEB patches are done)
        GetTickCount
        All_Debug - Applies ALL Debug detect patches ..

    o Anti-Process-finding Types:
        ZwQuerySystemInformation    (All other process apis use this)
        All_Process - Applies the debugger-process finding Api patch ..

    o Anti-Window-finding Types:
        FindWindowA
        FindWindowW
        FindWindowExA
        FindWindowExW
        EnumWindows
        All_Window - Applies ALL debugger-window finding Api patches ..


<dodgy excuse>
    Sorry for any weird code, I've only been using Python for 2 weeks .. :)
</dodgy excuse>


Description:
    Most of the functions are patched to return Debugger Found = False ..
    The PEB patches are to the various flags in PEB used by anti-debug ..
    Patch for ZwQueryInformationProcess is if DebugPort is checked, returns not debugged ..
    Patch for GetTickCount is to return same number everytime ..
    Patch for ZwQuerySystemInformation is to replace all ImmunityDebugger.exe with SVCHost.EXE ..
    Patch for Window finding apis call Api and if "ID" is classname then return not found ..


Maybe ToDo:
    o Patch CreateThread ?

"""


#-------------------------------------------------------------------------------
# Show usage ..

def usage(imm):
    imm.log(" ")
    imm.log("%s v%s By BoB -> Team PEiD" % (ProgName, ProgVers),focus=1, highlight=1)
    imm.log("Description:")
    imm.log("  Patches many different flags and apis used to detect debuggers ..")
    imm.log("  Different combinations of patches will defeat most protections, ")
    imm.log("   and some common anti-debug apis are patched with poly code ")
    imm.log("   to avoid detection by packers like RL!Pack .. ")
    imm.log("  All apis return usual valid data, the patches do not affect normal use .. ")
    imm.log("  EG: FindWindowA('NotePad.EXE', Null) will work same if patched or not..")
    imm.log(" ")
    imm.log("Usage:")
    imm.log("  !%s <Type>" % ProgName.lower())
    imm.log(" ")
    imm.log("Type can be ..")
    imm.log("  Debugger-Detect Types:")
    imm.log("  . IsDebuggerPresent          - Patches the Kernel32 Api to return false ..")
    imm.log("  . CheckRemoteDebuggerPresent - Patches the Kernel32 Api ..")
    imm.log("  . ZwQueryInformationProcess  - Patches the NtDll Api only for getting DebugPort ..")
    imm.log("  . GetTickCount               - Patches the Kernel32 Api to always return same value ..")
    imm.log("  . Peb                        - Patches PEB.IsDebugged, PEB.ProcessHeap.Flag, PEB.NtGlobalFlag and fill bytes ..")
    imm.log("  . All_Debug                  - Applies patches for all of the above .. ")
    imm.log(" ")
    imm.log("  Debugger-Detect by Process Types: ")
    imm.log("  . ZwQuerySystemInformation   - Patches the NtDll Api to remove ImmDbg from list ..")
    imm.log("  . All_Process                - Applies all process patches above .. ")
    imm.log(" ")
    imm.log("  Debugger-Detect by Window Types:  (User32.DLL must be loaded)")
    imm.log("  . FindWindowA                - Reports false if process looks for ImmDbg win classname ..")
    imm.log("  . FindWindowW                - Reports false if process looks for ImmDbg win classname ..")
    imm.log("  . FindWindowExA              - Reports false if process looks for ImmDbg win classname ..")
    imm.log("  . FindWindowExW              - Reports false if process looks for ImmDbg win classname ..")
    imm.log("  . EnumWindows                - Own callback function calls user callback if not ImmDbg HWnd ..")
    imm.log("  . All_Window                 - Applies all window patches above .. ")
    imm.log(" ")
    return "See log window (Alt-L) for usage .. "


#-------------------------------------------------------------------------------
# Misc functions ..
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
# Write Poly instructions to patch an EAX = Dword-Value instruction onto an Api ..

def Poly_ReturnDW(imm, Value):
    I = random.randint(1, 3)
    if I == 1:
        if random.randint(1, 2) == 1:
            # 7 bytes ..
            return imm.assemble( "Sub EAX, EAX\n Add EAX, 0x%08x" % Value )
        else:
            # 7 bytes ..
            return imm.assemble( "Sub EAX, EAX\n Sub EAX, -0x%08x" % Value )
    if I == 2:
        # 6 bytes
        return imm.assemble( "Push 0x%08x\n Pop EAX\n" % Value )
    if I == 3:
        if random.randint(1, 2) == 1:
            # 7 bytes with optimized instruction ..
            return imm.assemble( "XChg EAX, EDI\n DB 0xBF\n DD 0x%08x\n XChg EAX, EDI" % Value )
        else:
            # 8 bytes cos not optimized ..
            return imm.assemble( "XChg EAX, EDI\n Mov EDI, 0x%08x\n XChg EAX, EDI" % Value )


#-------------------------------------------------------------------------------
# Write Poly instructions to patch a simple EAX = 0 onto an Api ..

def Poly_Return0(imm):
    I = random.randint(1, 4)
    if I == 1:
        # 2 bytes
        return imm.assemble( "Sub EAX, EAX" )
    if I == 2:
        if random.randint(1, 2) == 1:
            # 6 bytes
            return imm.assemble( "Push 0\n Pop EAX" )
        else:
            # 3 bytes
            return imm.assemble( "DB 0x6A, 0x00\n Pop EAX" )
    if I == 3:
        # 4 bytes
        return imm.assemble( "XChg EAX, EDI\n Sub EDI, EDI\n XChg EAX, EDI" )
    if I == 4:
        return Poly_ReturnDW(imm, 0)


#-------------------------------------------------------------------------------
# Debug Detection Patches ..
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
# Clear various debug flags in PEB ..

def Patch_PEB(imm):
    PEB = imm.getPEBAddress()
    # Just incase .. ;)
    if PEB == 0:
        imm.log( "No PEB to patch .. !?" )
        return

    imm.log( "Patching PEB.IsDebugged ..", address = PEB + 0x02 )
    imm.writeMemory(PEB + 0x02, imm.assemble( "db 0" ) )

    a = imm.readLong(PEB + 0x18)
    a += 0x10
    imm.log( "Patching PEB.ProcessHeap.Flag ..", address = a )
    imm.writeLong( a, 0 )

    imm.log( "Patching PEB.NtGlobalFlag ..", address = PEB + 0x68 )
    imm.writeLong(PEB + 0x68, 0)

    # Patch PEB_LDR_DATA 0xFEEEFEEE fill bytes ..  (about 3000 of them ..)
    a = imm.readLong(PEB + 0x0C)
    imm.log("Patching PEB.LDR_DATA filling ..", address = a)
    while a != 0:
        a += 1
        try:
            b = imm.readLong(a)
            c = imm.readLong(a + 4)
            # Only patch the filling runs ..
            if (b == 0xFEEEFEEE) and (c == 0xFEEEFEEE):
                imm.writeLong(a, 0)
                imm.writeLong(a + 4, 0)
                a += 7
        except:
            break


#-------------------------------------------------------------------------------
# IsDebuggerPresent ..
# Note: This Api checks a value in PEB, so if patching PEB then no need to patch Api ..

def Patch_IsDebuggerPresent(imm):
    ispresent = imm.getAddress( "kernel32.IsDebuggerPresent" )
    # Just incase .. ;)
    if (ispresent <= 0):
        imm.log( "No IsDebuggerPresent to patch .." )
        return

    imm.log( "Patching IsDebuggerPresent...", address = ispresent )
    Code = imm.assemble("DB 0x64\n Mov EAX, DWORD PTR DS:[18]") + Poly_Return0(imm) + imm.assemble( "ret" )
    # Careful for Win2k ..
    while len(Code) > 0x0E:
      Code = imm.assemble("DB 0x64\n Mov EAX, DWORD PTR DS:[18]") + Poly_Return0(imm) + imm.assemble( "ret" )
    imm.writeMemory( ispresent, Code )


#-------------------------------------------------------------------------------
# CheckRemoteDebuggerPresent ..
# Note: This Api calls ZwQueryInformationProcess Api, so usually no need to patch both ..

def Patch_CheckRemoteDebuggerPresent(imm):
    deb = imm.getAddress( "kernel32.CheckRemoteDebuggerPresent" )
    # Just incase on Win2k .. ;)
    if (deb <= 0):
        imm.log( "No CheckRemoteDebuggerPresent to patch .." )
        return

    imm.log( "Patching CheckRemoteDebuggerPresent ..", address = deb )
    imm.writeMemory( deb, imm.assemble( " \
        Mov   EDI, EDI                                    \n \
        Push  EBP                                         \n \
        Mov   EBP, ESP                                    \n \
        Mov   EAX, [EBP + C]                              \n \
        Push  0                                           \n \
        Pop   [EAX]                                       \n \
        Xor   EAX, EAX                                    \n \
        Pop   EBP                                         \n \
        Ret   8                                           \
    " ) )


#-------------------------------------------------------------------------------
# ZwQueryInformationProcess ..

def Patch_ZwQueryInformationProcess(imm):
    qip = imm.getAddress( "ntdll.ZwQueryInformationProcess" )
    # Just incase .. ;)
    if (qip <= 0):
        imm.log( "No ZwQueryInformationProcess to patch .." )
        return

    imm.log( "Patching ZwQueryInformationProcess ..", address = qip )
    IsPatched = False
    a = 0
    s = 0
    # Scan Api and get size of first 2 instructions ..
    # On Win2k SysCall starts with Mov EAX, xxxxxxxx\n Lea EDX, [ESP + 4] ..
    # On WinXP, Win2k3 + Vista, SysCall always starts with Mov EAX, xxxxxxxx\n MOV EDX, 0x7FFE0300 ..
    while a < 2:
        a += 1
        s += imm.disasmSizeOnly(qip + s).opsize

    # Check if already patched ..
    FakeCode = imm.readMemory(qip, 1) + imm.assemble("DD 0x12345678") + imm.readMemory(qip + 5, 1)
    if FakeCode == imm.assemble( "Push 0x12345678\n Ret"):
        # Definately found a push jump ..
        IsPatched = True
        # Get address of where it points to ..
        a = imm.readLong(qip + 1)
        # Get length of the 2 instructions before patch code ..
        i = 0
        s = 0
        while i < 2:
            i += 1
            s += imm.disasmSizeOnly(a + s).opsize

    # If not patched already, allocate some memory for patch code ..
    if IsPatched == False:
        # Allocate memory for hook code ..
        a = imm.remoteVirtualAlloc(size=0x1000)
        # Write 2 instructions from api to allocated mem ..
        imm.writeMemory( a, imm.readMemory(qip, s) )

    # If ProcessInformationClass = ProcessDebugPort then return 0 in
    #  ProcessInformation; else call ZwQueryInformationProcess as normal ..
    PatchCode = " \
        Cmp    DWord [ESP + 8], 7           \n \
        DB     0x74, 0x06                   \n \
                                            \n \
        Push   0x%08X                       \n \
        Ret                                 \n \
                                            \n \
        Mov    EAX, DWord [ESP + 0x0C]      \n \
        Push   0                            \n \
        Pop    [EAX]                        \n \
        Xor    EAX, EAX                     \n \
        Ret    14                           \n \
    " % (qip + s)

    # Write patch code in allocated memory after the original first 2 instructions ..
    imm.writeMemory( a + s, imm.assemble( PatchCode ) )

    # If not patched, write Push Jmp to redirect Api to my code ..
    if IsPatched == False:
        imm.writeMemory( qip, imm.assemble( "Push 0x%08X\n Ret" % a) )


#-------------------------------------------------------------------------------
# GetTickCount ..
# Poly return cos it's an obvious one for a packer to check for Mov EAX, xxxxxxxx or Xor EAX, EAX ..

def Patch_GetTickCount(imm):
    a = imm.getAddress("kernel32.GetTickCount")
    # Just incase .. ;)
    if (a <= 0):
        imm.log( "No GetTickCount to patch .." )
        return

    imm.log("Patching GetTickCount ..", address = a)

    # Keep first instruction to avoid checks ..
    Code = imm.assemble("Mov EDX, 0x7FFE0000") + Poly_ReturnDW(imm, 0xB0B1560D) + imm.assemble("Ret")
    # Careful of Win2k's lack of alignment ..
    while len(Code) > 0x0F:
        Code = imm.assemble("Mov EDX, 0x7FFE0000") + Poly_ReturnDW(imm, 0xB0B1560D) + imm.assemble("Ret")
    
    imm.writeMemory( a, Code )


#-------------------------------------------------------------------------------
# ImmunityDbg.Exe Process detection Patches ..
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
# ZwQuerySystemInformation ..
# If called with size < needed size then just returns size ..
# If called with size >= needed size then fills buffer with list of all processes and lots of info about them ..

def Patch_ZwQuerySystemInformation(imm):
    qsi = imm.getAddress( "ntdll.ZwQuerySystemInformation" )
    # Just incase .. ;)
    if (qsi <= 0):
        imm.log( "No ZwQuerySystemInformation to patch .." )
        return

    imm.log("Patching ZwQuerySystemInformation ..", address = qsi)
    IsPatched = False
    a = 0
    s = 0
    # Scan Api and get size of first 3 instructions ..
    # On Win2k thats: Mov EAX, xxxxxxxx\n Lea EDX, [ESP + 4]\n Int 0x2E ..
    # On WinXP, Win2k3 + Vista thats: Mov EAX, xxxxxxxx\n MOV EDX, 0x7FFE0300\n Call [EDX] ..
    # So patch code will call SysCall before doing anything else ..
    while a < 3:
        a += 1
        s += imm.disasmSizeOnly(qsi + s).opsize

    # Check if already patched ..
    FakeCode = imm.readMemory(qsi, 1) + imm.assemble("DD 0x12345678") + imm.readMemory(qsi + 5, 1)
    if FakeCode == imm.assemble( "Push 0x12345678\n Ret"):
        # Definately found a push jump ..
        IsPatched = True
        # Get address of where it points to ..
        a = imm.readLong(qsi + 1)
        # Get length of the 3 instructions before patch code ..
        i = 0
        s = 0
        while i < 3:
            i += 1
            s += imm.disasmSizeOnly(a + s).opsize

    # If not patched already, allocate some memory for patch code ..
    if IsPatched == False:
        # Allocate memory for hook code ..
        a = imm.remoteVirtualAlloc(size=0x1000)
        # Write 3 instructions from api to allocated mem ..
        imm.writeMemory( a, imm.readMemory(qsi, s) )

    # If SystemInformationClass == SystemProcessesAndThreadsInformation then
    #  replace ImmunityDebugger.Exe with SVCHOST.EXE in returned process list .. :)
    # There are no labels, so all jmps, calls etc are written as bytes ..
    # Also, due to some weird bug LodsW assembles as LodsD so I put
    #  "DB 0x66\n LodsD" to force LodsW, and same for MovsW ..  (should work after bug fix)
    
    PatchCode = " \
                                        \n\
        Cmp     EAX, 0                  \n\
        DB      0x74, 0x03              \n\
        Ret     0x10                    \n\
                                        \n\
	    PushAD                          \n\
        Mov     EAX, [ESP + 0x24]       \n\
        Lea     EBX, [ESP + 0x28]       \n\
        Mov     ECX, [ESP + 0x2C]       \n\
                                        \n\
        DB      0xE8                    \n\
        DD      0x2C                    \n\
        DW      'I', 'M', 'M', 'U'      \n\
        DW      'N', 'I', 'T', 'Y'      \n\
        DW      'D', 'E', 'B', 'U'      \n\
        DW      'G', 'G', 'E', 'R'      \n\
        DW      '.', 'E', 'X', 'E'      \n\
        DW      0x00,0x00               \n\
                                        \n\
        Pop     EDI                     \n\
        Cmp     EAX, 5                  \n\
        DB      0x74, 0x04              \n\
        PopAD                           \n\
        Ret     0x10                    \n\
                                        \n\
        Cmp     ECX, 0                  \n\
        DB      0x74, 0xF4              \n\
        Cmp     EBX, 0                  \n\
        DB      0x74, 0xEC              \n\
                                        \n\
        Mov     EBX, [EBX]              \n\
	    PushAD                          \n\
        Xor     EAX, EAX                \n\
        Mov     ESI, [EBX + 0x3C]       \n\
        Cmp     ESI, 0                  \n\
        DB      0x74, 0x0A              \n\
        DB      0x66                    \n\
        LodsD                           \n\
        Cmp     EAX, 0                  \n\
        DB      0x75, 0x0C              \n\
                                        \n\
        Pop     EDI                     \n\
        Push    EDI                     \n\
        DB      0x8B, 0x03              \n\
        Or      EAX, EAX                \n\
        DB      0x74, 0x6F              \n\
        Add     EBX, EAX                \n\
        DB      0xEB, 0xDA              \n\
                                        \n\
        Cmp     AL, 0x61                \n\
        DB      0x7C, 0x03              \n\
        Sub     AL, 0x20                \n\
        Cmp     [EDI], AL               \n\
        DB      0x75, 0xE8              \n\
        Inc     EDI                     \n\
        Inc     EDI                     \n\
        Cmp     DWORD [EDI], 0          \n\
        DB      0x75, 0xD4              \n\
                                        \n\
        Sub     ESI, 0x28               \n\
                                        \n\
        DB      0xE8                    \n\
        DD      0x28                    \n\
        DW      'S', 'V', 'C', 'H'      \n\
        DW      'O', 'S', 'T', '.'      \n\
        DW      'E', 'X', 'E', 0x00     \n\
        DD      0x00,0x00,0x00,0x00     \n\
                                        \n\
        XChg    ESI, EDI                \n\
        Pop     ESI                     \n\
        Mov     ECX, 0x14               \n\
        DB      0x66                    \n\
        Rep     MovsD                   \n\
                                        \n\
        Mov     DWord [EBX + 0x40], 2   \n\
        Mov     DWord [EBX + 0x44], 0   \n\
        DB      0xEB, 0x89              \n\
                                        \n\
        PopAD                           \n\
        PopAD                           \n\
        Ret     0x10                    \n\
        \
    "

    # Write patch code in allocated memory after the original first 3 instructions ..
    imm.writeMemory( a + s, imm.assemble( PatchCode ) )

    # If not patched, write Push Jmp to redirect Api to my code ..
    if IsPatched == False:
        imm.writeMemory( qsi, imm.assemble( "Push 0x%08X\n Ret" % a) )


#-------------------------------------------------------------------------------
# Window Detection Patches ..
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
# Patch for FindWindowA, FindWindowW, FindWindowExA, FindWindowExW ..

def Patch_FindWindow(imm, ex = False, suffix = "A"):
    suffix = suffix.upper()

    RetVal = 0x08
    if ex:
       suffix = "Ex" + suffix
       RetVal = 0x10

    FW = imm.getAddress("user32.FindWindow%s" % suffix)
    # Just incase .. ;)
    if (FW <= 0):
        imm.log("No FindWindow%s to patch .. (Is User32 Loaded?)" % suffix)
        return False

    # Find place for jmp in Api ..
    p = 0
    d = imm.disasm(FW)
    l = d
    dis = ""
    FoundCall = False
    while p < 100:
        if d.getDisasm() == "POP EBP":
            dis = l.getDisasm()
            p -= l.getSize()
            if l.isCall():
                FoundCall = True
                break
            # Try to continue without expected call instrucion ..
            dis = l.getDisasm()
            break
        # Did we already patch this api ?
        if d.getDisasm() == "RETN":
            if l.isPush():
                imm.log("FindWindow%s already patched .." % suffix, address = FW)
                return False
        p += d.getSize()
        l  = d
        d  = imm.disasm(FW + p)

    imm.log("Patching FindWindow%s .." % suffix, address = FW)
    HookMem = imm.remoteVirtualAlloc(size=0x1000)
    HookCode = imm.assemble("Push 0x%08X\n Ret" % HookMem)

    if FoundCall == True:
        # Get address pointed to by call instruction ..
        a = l.getJmpAddr()
        # Fix Call instruction in patch function to point to original call address ..
        a = ((a - HookMem) - 5)
        dis = "DB 0xE8\n DD 0x%08X" % a

    # Get HWnd of ImmDbg ..  If this is exposed by ImmLib, I didn't find it.. :)
    ImmHWnd = ctypes.windll.LoadLibrary("User32.DLL").FindWindowA("ID", 0)

    # Code calls Api, if HWnd matches ImmDbg return 0 ..
    # Else all works as before ..
    # Again, all jumps are as bytes cos no labels ..

    PatchCode = " \
        %s                          \n\
        Cmp     EAX, 0x%08X         \n\
        DB      0x74, 0x02          \n\
        DB      0xEB, 0x02          \n\
        Xor     EAX, EAX            \n\
        Pop     EBP                 \n\
        Ret     0x%02X              \n\
    " % (dis, ImmHWnd, RetVal)

    imm.writeMemory(HookMem, imm.assemble(PatchCode))
    imm.writeMemory(FW + p, HookCode)
    return True


#-------------------------------------------------------------------------------

def Patch_EnumWindows(imm):
    EW = imm.getAddress("user32.EnumWindows")
    # Just incase .. ;)
    if (EW <= 0):
        imm.log("No EnumWindows to patch ..  (Is User32 Loaded?)")
        return False

    # Find place for jmp in Api ..
    p = 0
    d = imm.disasm(EW)
    l = d
    dis = ""
    FoundCall = False
    while p < 100:
        if d.getDisasm() == "POP EBP":
            dis = l.getDisasm()
            p -= l.getSize()
            if l.isCall():
                FoundCall = True
                break
            # Try to continue without expected call instrucion ..
            dis = l.getDisasm()
            break
        # Did we already patch this api ?
        if d.getDisasm() == "RETN":
            if l.isPush():
                imm.log("EnumWindows already patched ..", address = EW)
                return False
        p += d.getSize()
        l  = d
        d  = imm.disasm(EW + p)

    imm.log("Patching EnumWindows ..", address = EW)
    HookMem = imm.remoteVirtualAlloc(size=0x1000)
    HookCode = imm.assemble("Push 0x%08X\n Ret" % HookMem)

    if FoundCall == True:
        # Get address pointed to by call instruction ..
        a = l.getJmpAddr()
        # Fix Call instruction in patch function to point to original call address ..
        a = ((a - (HookMem + 0x5B)) - 5)  # 0x5B = offset of call instruction in patch code ..
        dis = "DB 0xE8\n DD 0x%08X" % a

    # Get HWnd of ImmDbg ..
    ImmHWnd = ctypes.windll.LoadLibrary("User32.DLL").FindWindowA("ID", 0)

    # Code calls Api, using own callback function ..
    # My callback calls user's callback function (if hwnd not ImmDbg) ..
    # Else all works as before ..
    PatchCode = " \
        DB      0xEB,0x31             \n\
                                      \n\
        Sub     EAX, EAX              \n\
        Inc     EAX                   \n\
        PushAD                        \n\
        DB      0x81,0x7C,0x24,0x24   \n\
        DD      0x%08X                \n\
        DB      0x74,0x1B             \n\
        Push    [ESP + 0x28]          \n\
        Push    [ESP + 0x28]          \n\
        Call    [0x0000002F]          \n\
        Mov     [ESP + 0x1C], EAX     \n\
        PopAD                         \n\
        Ret     8                     \n\
                                      \n\
        DD      0xB0b1560d            \n\
                                      \n\
        DB      0xE8                  \n\
        DD      0x00000000            \n\
        Pop     EAX                   \n\
        Sub     EAX, 0x38             \n\
        Add     [EAX + 0x20], EAX     \n\
        Push    [EBP + 0x08]          \n\
        Pop     [EAX + 0x2F]          \n\
                                      \n\
        Inc     EAX                   \n\
        Inc     EAX                   \n\
        Push    EAX                   \n\
        Pop     [ESP + 0x08]          \n\
        %s                            \n\
        Pop     EBP                   \n\
        Ret     8                     \n\
    " % (ImmHWnd, dis)

    imm.writeMemory(HookMem, imm.assemble(PatchCode))
    imm.writeMemory(EW + p, HookCode)
    return True


#-------------------------------------------------------------------------------
# Main Function ..

def main(args):
    ptypes={
            # Debug types
            'isdebuggerpresent':0, 'peb':1, 'checkremotedebuggerpresent':2,
              'zwqueryinformationprocess':3, 'gettickcount':4, 'all_debug':10,
            # Process Types
            'zwquerysysteminformation':20, 'all_process':21,
            # Window Types
            'findwindowa':30, 'findwindoww':31, 'findwindowexa':32, 'findwindowexw':33,
            'enumwindows':34, 'all_window':35,
            # Packers (some example ones - of course many more are supported, add them as you find them)
            'upx-lock':100, 'nspack':101, 'exestealth':102, 'escargot':103, 'rlpack':104
            }

    imm = immlib.Debugger()

    if not args:
        usage(imm)
        return "Error : No patch type ..  See log window for usage (Alt-L) .."

    ptype = args[0].lower()
    if ptypes.has_key( ptype ):
        ptype = ptypes[ ptype ]
    else:
        return "Invalid type: %s" % ptype

    # Intro text ..
    imm.log(" ")
    imm.log("%s v%s By BoB -> Team PEiD" % (ProgName, ProgVers), highlight=1)


    # --------------------------------------------------------------------------

    # IsDebuggerPresent ..
    # If patch PEB then no need for this ..
    if ptype == 0:
        Patch_IsDebuggerPresent(imm)
        return "IsDebuggerPresent patched .."

    # PEB ..
    elif ptype == 1:
        Patch_PEB(imm)
        return "PEB Flags patched .."

    # CheckRemoteDebuggerPresent ..
    # If patch ZwQueryInformationProcess then no need for this ..
    elif ptype == 2:
        Patch_CheckRemoteDebuggerPresent(imm)
        return "CheckRemoteDebuggerPresent patched .."

    # ZwQueryInformationProcess ..
    elif ptype == 3:
        Patch_ZwQueryInformationProcess(imm)
        return "ZwQueryInformationProcess patched .."

    # GetTickCount ..
    elif ptype == 4:
        Patch_GetTickCount(imm)
        return "GetTickCount patched .."

    # Patch all anti-debug / debug-detection Apis and flags ..
    elif ptype == 10:
        Patch_PEB(imm)
        Patch_IsDebuggerPresent(imm)
        Patch_CheckRemoteDebuggerPresent(imm)
        Patch_ZwQueryInformationProcess(imm)
        Patch_GetTickCount(imm)
        return "All Anti-debug Apis and flags patched .."


    # --------------------------------------------------------------------------
    # ZwQuerySystemInformation ..
    elif ptype == 20:
        Patch_ZwQuerySystemInformation(imm)
        return "ZwQuerySystemInformation patched .."

    # Patch all Process Apis to not return ImmDbg.EXE ..
    elif ptype == 21:
        Patch_ZwQuerySystemInformation(imm)
        return "All debugger process finding Apis patched .."


    # --------------------------------------------------------------------------
    # User32.DLL isn't always in memory, so these are done slightly differently ..

    # FindWindowA ..
    elif ptype == 30:
        if Patch_FindWindow(imm) == True:
            return "FindWindowA patched .."
        return "FindWindowA not patched .."

    # FindWindowW ..
    elif ptype == 31:
        if Patch_FindWindow(imm, "W") == True:
            return "FindWindowW patched .."
        return "FindWindowW not patched .."

    # FindWindowExA ..
    elif ptype == 32:
        if Patch_FindWindow(imm, True) == True:
            return "FindWindowExA patched .."
        return "FindWindowExA not patched .."

    # FindWindowExW ..
    elif ptype == 33:
        if Patch_FindWindow(imm, True, "W") == True:
            return "FindWindowExW patched .."
        return "FindWindowExW not patched .."

    # EnumWindows ..
    elif ptype == 34:
        if Patch_EnumWindows(imm) == True:
            return "EnumWindows patched .."
        return "EnumWindows not patched .."

    # All Window functions ..
    elif ptype == 35:
        a = True
        b = Patch_FindWindow(imm)
        if b == False:
            a = b
        b = Patch_FindWindow(imm, suffix = "W")
        if b == False:
            a = b
        b = Patch_FindWindow(imm, True, "A")
        if b == False:
            a = b
        b = Patch_FindWindow(imm, True, "W")
        if b == False:
            a = b
        b = Patch_EnumWindows(imm)
        if b == False:
            a = b
        if a:
            return "All debugger Window finding Apis patched .."
        return "Some Window Apis not patched ..  See Log .."


    # --------------------------------------------------------------------------

    # Fix Anti-Debug of Upx-Lock ..
    elif ptype == 100:
        Patch_IsDebuggerPresent(imm)
        Patch_GetTickCount(imm)
        return "ImmDbg hidden from Upx-Lock .."

    # Fix Anti-Debug of NsPack ..
    elif ptype == 101:
        Patch_PEB(imm)
        return "ImmDbg hidden from NsPack .."

    # Fix Anti-Debug of ExeStealth ..
    elif ptype == 102:
        Patch_PEB(imm)
        return "ImmDbg hidden from ExeStealth .."

    # Fix Anti-Debug of Escargot ..
    elif ptype == 103:
        Patch_IsDebuggerPresent(imm)
        return "ImmDbg hidden from Escargot .."

    # Fix Anti-Debug of RL!Pack (v1.18+ Still detects debug by guard page) ..
    elif ptype == 104:
        Patch_PEB(imm)
        Patch_ZwQueryInformationProcess(imm)
        Patch_EnumWindows(imm)
        return "ImmDbg hidden from RL!Pack .."


