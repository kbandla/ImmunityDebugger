"""
(c) 2007 Justin Seitz - jms@bughunter.ca

This is just a little script for ImmunityDebugger that will resolve
exposed COM functions to their relative address. Check usage for some TODO items.

NOTE: Requires comtypes http://sourceforge.net/projects/comtypes/
"""
from ctypes import *
from ctypes.wintypes import *
try:
   from comtypes import *
   from comtypes.typeinfo import *
   from comtypes.automation import *
except ImportError:
   raise ExceptionError, "Comtypes library needed"

from immlib import *

ole32 = windll.ole32
kernel32 = windll.kernel32

class MEMORY_BASIC_INFORMATION(Structure):

   _fields_ = [
      ('BaseAddress', c_void_p),
      ('AllocationBase', c_void_p),
      ('AllocationProtect', c_ulong),
      ('RegionSize', c_ulong),
      ('State', c_ulong),
      ('Protect', c_ulong),
      ('Type', c_ulong),
]

def get_linear_address(address):

   mbi = MEMORY_BASIC_INFORMATION()
   kernel32.VirtualQuery(address,byref(mbi),sizeof(mbi))
   return mbi.AllocationBase

def enum_type_info_members(p_iref_type_info,p_reftype_attr,p_iunknown,imm, base_addr):

   if p_reftype_attr.cFuncs == 0:
      return

   vtable = 0x0
   code_base = imm.getKnowledge("codebase")

   for i in range(p_reftype_attr.cFuncs):

      func_desc = p_iref_type_info.GetFuncDesc(i)
      method_name = p_iref_type_info.GetNames(func_desc.memid)
      inv_kind = func_desc.invkind


      lpVtbl = cast(p_iunknown, POINTER(POINTER(c_void_p)))

      value = get_linear_address(lpVtbl[0][func_desc.oVft])
      if str(method_name[0]) == "QueryInterface":
         import struct
         address = (((lpVtbl[0][i])-(value+0x1000)))
         address = address + code_base
         #activex = activex.split(".")[0]
         pages = imm.getMemoryPagebyOwnerAddress( base_addr ) # workaround
         for page in pages:
            mem = page.getMemory()
            ndx = mem.find( struct.pack("L", address) )
            if ndx != -1:
               vtable = page.getBaseAddress() + ndx
               break

      #imm.Log("values %s" % str(method_name[0]))

      if value is not None and lpVtbl[0][i] is not None:

         if func_desc.invkind == INVOKE_FUNC or func_desc.invkind == INVOKE_PROPERTYPUT or func_desc.invkind == INVOKE_PROPERTYPUTREF:
            address = (((lpVtbl[0][i])-(value+0x1000)))

            address = address + code_base
      else:
         if func_desc.invkind == INVOKE_FUNC or func_desc.invkind == INVOKE_PROPERTYPUT or func_desc.invkind == INVOKE_PROPERTYPUTREF:
            try:
               address = imm.readLong( vtable + i*4)
            except Exception:
               address = 0
      imm.Log("Method: %s Address: 0x%08x" % (str(method_name[0]),address),address)

def usage(imm):

   imm.Log("This is a helper for RE/bughunting ActiveX controls.")
   imm.Log("!activex <name of Control>                          -    this outputs all functions and their addresses.")
   imm.Log("!activex <name of Control> break <function name>    -    set a breakpoint on a function name.")
   imm.Log("!activex <name of Control> exec <function name>     -    call the function internally.")
   imm.Log("!activex <name of Control> fuzz <function name>     -    fuzz this function.")


def main(args):
   imm = Debugger()

   try:
      if args[0]:
         if len(args) > 1:
            if args[1]:

               if args[1] == "break":
                  mode = "break_on_func"
                  func = args[2]

               if args[1] == "exec":
                  mode = "exec_func"
                  func = args[2]

               if args[1] == "fuzz":
                  mode = "fuzz_func"
                  func = args[2]

         else:
            activex = args[0]
      else:
         usage(imm)
         return "Usage Information Outputted"
   except:
      usage(imm)
      return "Usage Inforamtion Outputted"

   module = imm.getModule(activex)
   imm.addKnowledge("codebase",module.getCodebase(),force_add=1)

   tlib = LoadTypeLib(module.getPath())

   ticount = tlib.GetTypeInfoCount()

   i = 0

   while i < ticount:

      p_itype_info = tlib.GetTypeInfo(i)

      if p_itype_info:
         p_type_attr = p_itype_info.GetTypeAttr()

         if p_type_attr.typekind is TKIND_COCLASS:

            for ref in range(p_type_attr.cImplTypes):
               h_ref_type = p_itype_info.GetRefTypeOfImplType(ref)

               if h_ref_type:

                  p_iref_type_info = p_itype_info.GetRefTypeInfo(h_ref_type)

                  if p_iref_type_info:
                     p_reftype_attr = p_iref_type_info.GetTypeAttr() 
                     imm.Log("CLSID: %s " % str(p_type_attr.guid))
                     #try:

                     p_iunknown = CoCreateInstance(p_type_attr.guid)
                     #except:
                     #   pass

                     if p_iunknown:

                        enum_type_info_members(p_iref_type_info,p_reftype_attr,p_iunknown,imm, module.getBaseAddress())



      i+=1

   return "ActiveX Methods Trapped"
