"""
recognize.py - Function Recongnizing using heuristic patterns.

(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}

"""


__VERSION__ = '1.0'
import immlib
import immutils
import getopt
import string
import os
import csv
from librecognition import *

DESC="Function Recognizing using heuristic patterns."

def usage(imm):
    imm.log("!recognize -{a|m} -n name [ -x address ] [ -i filename ] [-v version/extra]")
    imm.log("!recognize -d [ -i filename ] -n name")
    imm.log("!recognize -l [-i filename] [-n name]")
    imm.log("!recognize -f -n name [-i filename] [-v version/extra] [-o module] [-h heuristic_threasold]")
    imm.log("!recognize -r -x address [-i filename] [-h heuristic_threasold]")
    imm.log("  ex (find a pattern, accept 80%% of match): !recognize -f -n iTunes.AntiDebuggers -h 80 -o iTunes.exe")
    imm.log("  ex (resolv an address, accept 93%% of match): !recognize -r -x 004EDE00 -h 93")
    imm.log("  ex (add a pattern): !recognize -a -x 004EDE00 -n iTunes.AntiDebuggers -i itunes.dat -v 7.4.1")
    imm.log("  ex (add a pattern guessing the address from labels or symbols): !recognize -a -n _SPExternalAlloc@4")
    imm.log("  ex (modify a pattern): !recognize -m -x 004EDE00 -n iTunes.AntiDebuggers -i itunes.dat -v protections_disabled")
    imm.log("  ex (delete a pattern): !recognize -d -i itunes.dat -n iTunes.AntiDebuggers")
    imm.log("  ex (list patterns): !recognize -l -i itunes.dat -n antidebug", focus=1)
    return ""

def main(args):
    imm = immlib.Debugger()

    imm.log("################# Immunity's Function Recognizing ################")
    imm.markBegin()
    
    if not args:
        usage(imm)
        return "not enough args"

    try:
        opts, notused = getopt.getopt(args, "amdlfrx:n:i:h:v:o:")
    except getopt.GetoptError:
        usage(imm)
        return "Wrong Arguments (Check usage on the Log Window)"

    defaultfilename = os.path.join("Data", "default.dat")
    name = address = id = action = module = filename = None
    version = ""
    heuristic = 90
    for o,a in opts:
        if o == '-x':
            address = imm.getAddress(a)
            if address < 0:
                imm.log("invalid address or expresion")
                usage(imm)
                return "address error!"
        if o == '-o':
            module = a
        if o == '-n':
            name = string.strip(a, " '\"\\{}%;,")
        if o == "-i":
            filename = os.path.basename(string.strip(a, " '\"{}%;,"))+".dat"
            if not filename:
                usage(imm)
                return "invalid filename"
            filename = os.path.join("Data",filename)
        if o == '-v':
            version = string.strip(a, " '\"\\{}%;,")
        if o == "-h":
            try:
                heuristic = int(a)
            except:
                imm.log("invalid heuristic threasold")
                usage(imm)
                return "heuristic theashold error!"
        if o in ["-a","-m","-d","-l","-f","-r"]:
            action = o[1]
    
    if not action:
        usage(imm)
        return "no action set"
    
    #add/modify an element
    if action == "a" or action == "m":
        if not filename: filename = defaultfilename
        if not name:
            usage(imm)
            return "insufficient arguments to add/modify an entry"
        
        if not address:
            tmp = imm.getAddressOfExpression(name)
            if tmp > 0:
                address = tmp
            else:
                return "name hasn't a known address"

        modif = False
        recon = FunctionRecognition(imm, filename)
        for d in recon.dictionaries:
            if name == d[0]:
                if action == "a":
                    usage(imm)
                    return "the name '%s' is already in the selected dictionary" % name
                if action == "m":
                    modif = True
                    break
        if action == "m" and not modif:
            usage(imm)
            return "the name '%s' wasn't found in the selected dictionary" % name
        
        tmp  = recon.makeFunctionHash(address, compressed=True)
        file = extractFile(imm, address)
        definition = [ name, tmp[0], tmp[1][0], tmp[1][1], tmp[2], version, file, string.join(tmp[3],"|") ]
        remakeDictionary(imm, recon, filename, definition, action)
        imm.log("Element '%s' added/modified" % name, focus=1)

    #delete an element
    if action == "d":
        if not name:
            usage(imm)
            return "incomplete information to delete an element"
        if not filename: filename = defaultfilename
        delete = False
        recon = FunctionRecognition(imm, filename)
        for d in recon.dictionaries:
            if name == d[0]:
                delete = True
                break
        if not delete:
            usage(imm)
            return "the function '%s' wasn't found in the selected dictionary" % name
        remakeDictionary(imm, recon, filename, name, action)
        imm.log("Element '%s' deleted" % name, focus=1)

    #list elements
    if action == "l":
        recon = FunctionRecognition(imm, filename)
        list = []
        for values in recon.dictionaries:
            if not name or name.lower() in values[0].lower():
                list.append([values[0],values[5],values[6],values[4], os.path.basename(values[-1])[:-4]])
        if not list:
            return "the name '%s' wasn't found in the dictionaries" % name
        else:
            imm.log("-" * 156)
            imm.log("|%-30s|%-40s|%-20s|%-40s|%-20s|" % ("real name","version/extra","binary file","SHA1","repository"))
            imm.log("-" * 156)
            for v in list:
                imm.log("|%-30s|%-40s|%-20s|%-40s|%-20s|" % (v[0][0:30],v[1][0:40],v[2][0:20],v[3][0:40], v[4][0:20]), focus=1)
            imm.log("-" * 156)
    
    #search for an element
    if action == "f":
        if not name:
            usage(imm)
            return "incomplete information to search"
        
        #we need to maintain separated csv indexes 
        dict = FunctionRecognition(imm, filename)
        recon = FunctionRecognition(imm, filename)
        addy = None
        for values in dict.dictionaries:
            if name.lower() in values[0].lower():
                tmp = recon.searchFunctionByName(values[0], heuristic, module, version)
                if tmp:
                    for addy,heu in tmp:
                        imm.log("Function '%s' address: %08X (%d%%)" % (values[0], addy,heu), addy, focus=1)
        if addy:
            imm.gotoDisasmWindow(addy)
        else:
            imm.log("We can't find a function that fullfit all the requirements", focus=1)

    #resolv an address to a function name
    if action == "r":
        if not address:
            usage(imm)
            return "we need an address to resolv"

        recon = FunctionRecognition(imm, filename)
        name = recon.resolvFunctionByAddress(address)
        if name:
            imm.log("function at %08X FOUND: %s" % (address, name), address, focus=1)
            imm.gotoDisasmWindow(address)
        else:
            imm.log("function not found", focus=1)
        
    return "Done in %d secs! see the log for details" % imm.markEnd()

def remakeDictionary(imm, recon, filename, data, action):
    tmpfd = os.tmpfile()
    writer = csv.writer(tmpfd)
    if action == "a" or action == "m":
        writer.writerow(data)
    
    for row in recon.dictionaries:
        row.pop() #drop the filename added by the CSV iterator (always the last element)
        if action == "a":
            writer.writerow(row)
        if action == "m" and data[0] != row[0]:
            writer.writerow(row)
        if action == "d" and data != row[0]:
            writer.writerow(row)
    tmpfd.flush()
    del recon
    del writer
    
    fd = open(filename, "wb")
    tmpfd.seek(0)
    for line in tmpfd:
        fd.write(line)
    tmpfd.close()
    fd.close()

def extractFile(imm, address):
    for mod in imm.getAllModules().values():
        if mod.getBaseAddress() <= address and address <= mod.getBaseAddress()+mod.getSize():
            return os.path.basename(mod.getPath())
    return ""
