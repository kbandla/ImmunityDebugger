"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}

Search a defined memory range looking for cryptographic routines
"""


__VERSION__ = '1.0'
import immlib
import getopt
from immutils import *

DESC = "Search a defined memory range looking for cryptographic routines"

def usage(imm):
    imm.log("!searchcrypt [-a FROMADDRESS] [-t TOADDRESS] [-o OWNER]", focus=1)
    imm.log("    FROMADDRESS    start address")
    imm.log("    TOADDRESS      end address")
    imm.log("    OWNER          memory page owner")
    imm.log("ex: !searchcrypt -a 0x70000000")

def main(args):
    imm = immlib.Debugger()

    try:
        opts, notused = getopt.getopt(args, "a:t:o:")
    except getopt.GetoptError:
        usage(imm)
        return "Wrong Arguments (Check usage on the Log Window)"

    fromaddy = toaddy = owner = None
    
    for o,a in opts:
        if o == '-a':
            try:                
                fromaddy = int( a, 16 )
            except ValueError:
                usage(imm)                  
                return "Wrong Address (%s) % " % a
        if o == '-t':
            try:                
                toaddy = int( a, 16 )
            except ValueError:
                usage(imm)                  
                return "Wrong Address (%s) % " % a
        if o == '-o':
            owner = a

    if isinstance(toaddy, int) and isinstance(fromaddy, int) and toaddy <= fromaddy:
        usage(imm)
        return "end address can't be less than start address"

    result = []

    #the first dword has to be unique in the complete dictionary to get an accurate address
    consts = {
                  "AES": [ 0xc66363a5, 0xf87c7c84, 0xee777799, 0xf67b7b8d, 0xfff2f20d, 0xd66b6bbd, 0xde6f6fb1, 0x91c5c554, 0x60303050, 0x02010103, 0xce6767a9, 0x562b2b7d, 0xe7fefe19, 0xb5d7d762, 0x4dababe6, 0xec76769a, 0x8fcaca45, 0x1f82829d, 0x89c9c940, 0xfa7d7d87, 0xeffafa15, 0xb25959eb, 0x8e4747c9, 0xfbf0f00b, 0x41adadec, 0xb3d4d467, 0x5fa2a2fd, 0x45afafea, 0x239c9cbf, 0x53a4a4f7, 0xe4727296, 0x9bc0c05b, 0x75b7b7c2, 0xe1fdfd1c, 0x3d9393ae, 0x4c26266a, 0x6c36365a, 0x7e3f3f41, 0xf5f7f702, 0x83cccc4f, 0x6834345c, 0x51a5a5f4, 0xd1e5e534, 0xf9f1f108, 0xe2717193, 0xabd8d873, 0x62313153, 0x2a15153f, 0x0804040c, 0x95c7c752, 0x46232365, 0x9dc3c35e, 0x30181828, 0x379696a1, 0x0a05050f, 0x2f9a9ab5 ], \
             "BLOWFISH": [ 0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89, 0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c, 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917, 0x9216d5d9, 0x8979fb1b ], \
             "CAMELLIA": [ 0xA09E667F, 0x3BCC908B, 0xB67AE858, 0x4CAA73B2, 0xC6EF372F, 0xE94F82BE, 0x54FF53A5, 0xF1D36F1C, 0x10E527FA, 0xDE682D1D, 0xB05688C2, 0xB3E6C1FD ], \
                 "CAST": [ 0x30fb40d4, 0x9fa0ff0b, 0x6beccd2f, 0x3f258c7a, 0x1e213f2f, 0x9c004dd3, 0x6003e540, 0xcf9fc949, 0xbfd4af27, 0x88bbbdb5, 0xe2034090, 0x98d09675, 0x6e63a0e0, 0x15c361d2, 0xc2e7661d, 0x22d4ff8e, 0x28683b6f, 0xc07fd059, 0xff2379c8, 0x775f50e2, 0x43c340d3, 0xdf2f8656, 0x887ca41a, 0xa2d2bd2d, 0xa1c9e0d6, 0x346c4819, 0x61b76d87, 0x22540f2f, 0x2abe32e1, 0xaa54166b, 0x22568e3a, 0xa2d341d0, 0x66db40c8, 0xa784392f, 0x004dff2f, 0x2db9d2de, 0x97943fac, 0x4a97c1d8, 0x527644b7, 0xb5f437a7, 0xb82cbaef, 0xd751d159, 0x6ff7f0ed, 0x5a097a1f, 0x827b68d0, 0x90ecf52e, 0x22b0c054, 0xbc8e5935, 0x4b6d2f7f, 0x50bb64a2, 0xd2664910, 0xbee5812d, 0xb7332290, 0xe93b159f, 0xb48ee411, 0x4bff345d, 0xfd45c240, 0xad31973f, 0xc4f6d02e, 0x55fc8165, 0xd5b1caad, 0xa1ac2dae, 0xa2d4b76d, 0xc19b0c50, 0x882240f2, 0x0c6e4f38, 0xa4e4bfd7, 0x4f5ba272, 0x564c1d2f, 0xc59c5319, 0xb949e354, 0xb04669fe, 0xb1b6ab8a, 0xc71358dd, 0x6385c545, 0x110f935d, 0x57538ad5, 0x6a390493, 0xe63d37e0, 0x2a54f6b3, 0x3a787d5f, 0x6276a0b5, 0x19a6fcdf, 0x7a42206a, 0x29f9d4d5, 0xf61b1891, 0xbb72275e, 0xaa508167, 0x38901091, 0xc6b505eb, 0x84c7cb8c, 0x2ad75a0f, 0x874a1427, 0xa2d1936b, 0x2ad286af, 0xaa56d291, 0xd7894360, 0x425c750d, 0x93b39e26, 0x187184c9, 0x6c00b32d, 0x73e2bb14, 0xa0bebc3c, 0x54623779 ], \
                  "MD5": [ 0xd76aa478, 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ], \
                  "RC2": [ 0xc4f978d9, 0xedb5dd19, 0x79fde928, 0x9dd8a04a, 0x83377ec6, 0x8e53762b, 0x88644c62, 0xa2fb8b44, 0xf5599a17, 0x134fb387, 0x8d6d4561, 0x327d8109, 0xeb408fbd, 0x0b7bb786, 0x222195f0, 0x824e6b5c, 0x9365d654, 0x1cb260ce, 0x14c05673, 0xdcf18ca7, 0x1fca7512, 0xd1e4be3b, 0x30d43d42, 0x26b63ca3, 0xda0ebf6f, 0x57076946, 0x9b1df227, 0x034394bc, 0xf6c711f8, 0xe73eef90, 0x2fd5c306, 0xd71e66c8, 0xdeeae808, 0xf7ee5280, 0xac72aa84, 0x2a6a4d35, 0x71d21a96, 0x7449155a, 0x5ed09f4b, 0xeca41804, 0x6e41e0c2, 0xcccb510f, 0x50af9124, 0x3970f4a1, 0x853a7c99, 0x7ab4b823, 0x5b3602fc, 0x31975525, 0x98fa5d2d, 0xae928ae3, 0x1029df05, 0xc9ba6c67, 0xcfe600d3, 0x2ca89ee1, 0x3f011663, 0xa989e258, 0x1b34380d, 0xb0ff33ab, 0x5f0c48bb, 0x2ecdb1b9, 0x47dbf3c5, 0x779ca5e5, 0x6820a60a, 0xadc17ffe ], \
                  "RC5": [ 0xb7e15163, 0x9e3779b9 ], \
            "RIPEMD160": [ 0x50A28BE6, 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0, 0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9 ], \
                 "SHA1": [ 0xCA62C1D6, 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC ], \
               "SHA256": [ 0xc67178f2, 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19, 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7 ], \
               "SHA512": [ 0xf3bcc908, 0x6a09e667, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1, 0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f, 0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179, 0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc, 0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019, 0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118, 0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2, 0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694, 0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3, 0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65, 0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483 ] \
             }

    result = MultiSearch(imm, consts, fromaddy, toaddy, owner)

    for name,addy in result:
        mem = imm.getMemoryPageByAddress(addy)
        imm.log("Const Found: %10s Owner: %s - Section: %s" % ( name, mem.getOwner(), \
                                                                  mem.getSection() ), addy )

    return "search finished"


def MultiSearch(imm, consts, fromaddy, toaddy, arg_owner):
    if not consts:
        return []
    
    found = []
    hits = {}
    addys = {}
    
    for a in imm.getMemoryPages().keys():
        if isinstance(fromaddy, int) and a < fromaddy:
            continue

        if isinstance(toaddy, int) and a > toaddy:
            continue

        owner = imm.MemoryPages[a].getOwner()

        if isinstance(arg_owner, str) and owner.upper() != arg_owner.upper():
            continue

        mem = imm.MemoryPages[a].getMemory()

        if not mem:
            continue

        for name,consts_list in consts.iteritems():
            
            if not isinstance(consts_list,list):
                consts_list = [ consts_list ]

            count = 0
            for const in consts_list:
                const = int2str32_swapped(const)

                f = mem.find ( const )

                if f == -1:
                    continue

                #check if it's outside the scope of my search
                if isinstance(toaddy, int) and (f + a) > toaddy:
                    break
                
                #we save the hits by owner
                try:
                    hits[name][owner] += 1
                except KeyError:
                    if not hits.has_key(name):
                        hits[name] = {}
                    hits[name][owner] = 1
                
                #get the address of the first hit
                if not addys.has_key(name):
                    addys[name] = {}
                if not addys[name].has_key(owner):
                    addys[name][owner] = f + a

            
    # it has to match every const to get a real match
    for name,consts_list in consts.iteritems():
        if hits.has_key(name):
            for owner,count in hits[name].iteritems():
                if count >= len(consts_list):
                    found.append( [name, addys[name][owner] ] )

    return found
