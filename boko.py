# Author: Jesse Nebling (@bashexplode)
# The dylib scanning functions are based off of Patrick Wardle's tool Dylib Hijack Scanner
#
# boko.py is a static application scanner for macOS that searches for and identifies
# potential dylib hijacking and weak dylib vulnerabilities for application executables, as well as
# identifies scripts an application may use that have the potential to be backdoored. It also calls out interesting
# files and lists them instead of manually browsing the file system for analysis.
#
# Dictionary format:
# Filepath: {
#   'writeable': Bool, # indicates whether or not the current user that ran the tool has write permissions on the file
#   'execution': { # dictionary for execution output, only applicable if the --active or --both flag is used
#       'standardoutput': [],
#       'erroroutput' []
#    },
#   'load': {
#       'LC_RPATHs': [],
#       'LC_LOAD_WEAK_DYLIBs': [],
#       'LC_LOAD_DYLIBs': []
#    },
#   'filetypeh': 'String', # indicates the file type as a string : Executable, Dylib, Bundle, KextBundle, Script, Misc (based on file extension)
#   'filetype': mach_header filetype,
#   'parse': 'String', # indicates if the file was an executable and was parsed for weaknesses
#   'filename': 'String', # File name without full path
#   'vulnerable': {
#       'WeakDylib': [ # list of weak dylibs, each weak dylib has its own dictionary
#           {
#               'Certainty': 'String', # indicates how certain the vulnerability exists based on load path ordering and file type : Definite, High, Potential, Low
#               'hijackPath': 'String', # full path a malicious dylib can be placed to hijack the load order of the base file
#               'WriteAccess': Bool, # indicates whether or not the current user that ran the tool can write to the hijackPath
#               'LoadOrder': int, # indicates the order in which the main binary Filename loads the dylib relative path, starts at 0
#               'ReadOnlyPartition': False # indicates whether or not the directory is in a SIP-protected partition
#           }
#        ],
#       'DylibHijack': [ # list of hijackable dylibs, each dylib has its own dictionary
#           {
#               'Certainty': 'String', # indicates how certain the vulnerability exists based on load path ordering and file type : Definite, High, Potential, Low
#               'hijackPath': 'String', # full path a malicious dylib can be placed to hijack the load order of the base file
#               'WriteAccess': Bool, # indicates whether or not the current user that ran the tool can write to the hijackPath
#               'LoadOrder': int, # indicates the order in which the main binary Filename loads the dylib relative path, starts at 0
#               'ReadOnlyPartition': False # indicates whether or not the directory is in a SIP-protected partition
#           }
#        ],
#       'BackdoorableScript': [ # list of potentially backdoorable scripts, each script has its own dictionary
#           {
#               'Certainty': 'String', # indicates how certain the vulnerability exists based on load path ordering and file type : Definite, High, Potential, Low
#               'hijackPath': 'String', # full path a malicious dylib can be placed to hijack the load order of the base file
#               'WriteAccess': Bool, # indicates whether or not the current user that ran the tool can write to the hijackPath
#               'LoadOrder': int, # indicates the order in which the main binary Filename loads the dylib relative path, starts at 0
#               'ReadOnlyPartition': False # indicates whether or not the directory is in a SIP-protected partition
#           }
#        ]
#    }
# }

from __future__ import print_function
import ctypes
import argparse
import os
import sys
import io
import struct
import psutil
import subprocess
from datetime import datetime
from multiprocessing.dummy import Pool as ThreadPool
import threading

screenlock = threading.Semaphore(value=1)


class mach_header(ctypes.Structure):
    _fields_ = [
        ("magic", ctypes.c_uint),
        ("cputype", ctypes.c_uint),
        ("cpusubtype", ctypes.c_uint),
        ("filetype", ctypes.c_uint),
        ("ncmds", ctypes.c_uint),
        ("sizeofcmds", ctypes.c_uint),
        ("flags", ctypes.c_uint)
    ]


class mach_header_64(ctypes.Structure):
    _fields_ = mach_header._fields_ + [('reserved', ctypes.c_uint)]


class load_command(ctypes.Structure):
    _fields_ = [
        ("cmd", ctypes.c_uint),
        ("cmdsize", ctypes.c_uint)
    ]


class ExecutableScanner:
    def __init__(self, verbose, sipdisabled):
        self.verbose = verbose
        self.results = {}
        self.sipreadonlydefaults = ['//',
                                    '/.fseventsd',
                                    '/.vol',
                                    '/System',
                                    '/System/Applications',
                                    '/System/DriverKit',
                                    '/System/Library',
                                    '/System/Volumes',
                                    '/System/iOSSupport',
                                    '/bin',
                                    '/private/var',
                                    '/sbin',
                                    '/usr',
                                    '/usr/bin',
                                    '/usr/lib',
                                    '/usr/libexec',
                                    '/usr/sbin',
                                    '/usr/share',
                                    '/usr/standalone',
                                    '/Library/Developer/CommandLineTools/SDKs/']
        self.uninterestingexts = ['.3pm', '.3', '.3tcl', '.3x', '.3g', '.aiff', '.dll', '.doc', '.dub', '.dylib', '.filters', '.frag', '.gif', '.html', 
                                  '.icns', '.idm', '.iqy', '.lab', '.lex', '.manifest', '.meta', '.metainfo', 
                                  '.mp4', '.nls', '.node', '.nrr', '.odf', '.olb', '.plist', '.png', '.ppd', '.ppt', '.pst', '.qml',
                                  '.qmltypes', '.qrc', '.svg', '.tib', '.tiff', '.tlb', '.transition', '.ttc', '.ttf', '.typ',
                                  '.vert', '.wmf', '.xlam', '.xll', '.xls', '.jpg', '.jpeg', '.bmp', '.css', '.tif', '.nib', '.strings', '.tcl', '.wav', '.pcm', '.mp3']
        self.knownpopscriptexts = ['.applescript', '.scpt', '.command', '.sh', '.py', '.rb', '.pl', '.lua', '.jsp',
                                   '.jxa', '.php']

        if sipdisabled:
            self.readonly = None
            self.sipdisabled = True
        else:
            self.readonly = self.sipreadonlydefaults
            self.sipdisabled = False

        # supported archs
        self.SUPPORTED_ARCHITECTURES = ['i386', 'x86_64']

        self.LC_REQ_DYLD = 0x80000000
        self.LC_LOAD_WEAK_DYLIB = self.LC_REQ_DYLD | 0x18
        self.LC_RPATH = (0x1c | self.LC_REQ_DYLD)
        self.LC_REEXPORT_DYLIB = 0x1f | self.LC_REQ_DYLD

        (
            self.LC_SEGMENT, self.LC_SYMTAB, self.LC_SYMSEG, self.LC_THREAD, self.LC_UNIXTHREAD, self.LC_LOADFVMLIB,
            self.LC_IDFVMLIB, self.LC_IDENT, self.LC_FVMFILE, self.LC_PREPAGE, self.LC_DYSYMTAB, self.LC_LOAD_DYLIB,
            self.LC_ID_DYLIB, self.LC_LOAD_DYLINKER, self.LC_ID_DYLINKER, self.LC_PREBOUND_DYLIB,
            self.LC_ROUTINES, self.LC_SUB_FRAMEWORK, self.LC_SUB_UMBRELLA, self.LC_SUB_CLIENT,
            self.LC_SUB_LIBRARY, self.LC_TWOLEVEL_HINTS, self.LC_PREBIND_CKSUM
        ) = range(0x1, 0x18)

        self.MH_MAGIC = 0xfeedface
        self.MH_CIGAM = 0xcefaedfe
        self.MH_MAGIC_64 = 0xfeedfacf
        self.MH_CIGAM_64 = 0xcffaedfe

        self._CPU_ARCH_ABI64 = 0x01000000
        self.CPU_TYPE_NAMES = {
            -1: 'ANY',
            1: 'VAX',
            6: 'MC680x0',
            7: 'i386',
            self._CPU_ARCH_ABI64 | 7: 'x86_64',
            8: 'MIPS',
            10: 'MC98000',
            11: 'HPPA',
            12: 'ARM',
            13: 'MC88000',
            14: 'SPARC',
            15: 'i860',
            16: 'Alpha',
            18: 'PowerPC',
            self._CPU_ARCH_ABI64 | 18: 'PowerPC64',
        }

        # executable binary
        self.MH_EXECUTE = 2

        # dylib
        self.MH_DYLIB = 6

        # bundles
        self.MH_BUNDLE = 8

        # kext bundle
        self.MH_KEXT_BUNDLE = 0xb
        self.LC_Header_Sz = 0x8

    def isSupportedArchitecture(self, machoHandle):
        machoHandle.seek(0)
        headersz = 28
        header64sz = 32
        supported = False
        header = ""
        try:
            magic = struct.unpack('<L', machoHandle.read(4))[0]
            machoHandle.seek(0, io.SEEK_SET)

            if magic == self.MH_MAGIC or magic == self.MH_CIGAM:
                headert = mach_header.from_buffer_copy(machoHandle.read(headersz))
                # print("CPUType: %s" % headert.cputype)
                if self.CPU_TYPE_NAMES.get(headert.cputype) == 'i386':
                    supported = True
                    header = headert
            elif magic == self.MH_MAGIC_64 or magic == self.MH_CIGAM_64:
                headert = mach_header_64.from_buffer_copy(machoHandle.read(header64sz))
                # print("CPUType: %s" % headert.cputype)
                if self.CPU_TYPE_NAMES.get(headert.cputype) == 'x86_64':
                    supported = True
                    header = headert
            else:
                header = None
        except:
            pass

        return supported, header

    def scriptCheck(self, file, filename, fullpath):
        file.seek(0)
        if file.read(2) == '#!':
            contents = file.read(50)
            scripttype = contents.split('\n')[0].split('/')[-1]
            file.seek(0)
            self.results[fullpath]["script"] = scripttype
            self.results[fullpath]["parse"] = "Script"
            self.results[fullpath]['filetypeh'] = "Script"
            return True
        elif '.' in filename and os.path.splitext(filename)[-1] in self.knownpopscriptexts:
            self.results[fullpath]["script"] = filename.split('.')[-1]
            self.results[fullpath]["parse"] = "Script"
            self.results[fullpath]['filetypeh'] = "Script"
            return True
        else:
            return False

    def initializeDictionaryItem(self, filename, filepath, parse):
        self.results[filepath] = {}
        self.results[filepath]["filename"] = filename
        self.results[filepath]["parse"] = parse
        self.results[filepath]["mode"] = "Passive"
        self.writeCheck(filepath)

    def writeCheck(self, filepath):
        if os.access(filepath, os.W_OK):
            self.results[filepath]["writeable"] = True
        else:
            self.results[filepath]["writeable"] = False

    def readWriteCheck(self, rpath):
        # Check if current user context has write permissions to the last existing path
        lastexistingpath = '/'
        for i in range(2, len(rpath.split('/'))):
            checkpath = '/'.join(rpath.split('/')[0:i])
            if os.path.exists(checkpath):
                lastexistingpath = checkpath

        if os.access(lastexistingpath, os.W_OK):
            contextwriteperm = True
        else:
            contextwriteperm = False

        # Check if rpath is in the read only partition
        if rpath.startswith(tuple(self.readonly)):
            readonlypartition = True
        else:
            readonlypartition = False

        return readonlypartition, contextwriteperm

    def loadedBinaries(self):
        if self.verbose:
            print("[*] Identifying potential hijackable processes currently running")
        for proc in psutil.process_iter(['pid', 'name', 'username', 'exe']):
            if proc.info["exe"] is not None and not proc.info["exe"].startswith(tuple(self.readonly)):
                if proc.info["name"] not in self.results.keys():
                    self.initializeDictionaryItem(str(proc.info["name"]).strip(), str(proc.info["exe"]).strip(), True)
                    if self.verbose:
                        print("[+] Found: %s" % proc.info["exe"])
        if self.verbose:
            print("[+] Finished gathering running processes in %s")

    def installedBinaries(self, rootDirectory='/'):
        if self.verbose:
            print("[*] Identifying potential hijackable process in %s" % rootDirectory)
        applications = []
        if '.app' in rootDirectory:
            indices = [i for i, x in enumerate(rootDirectory.split('/')) if ".app" in x]
            applications.append('.'.join(rootDirectory.split('/')[indices[-1]].split('.')[:-1]))

        for root, dirnames, filenames in os.walk(rootDirectory):
            if root.startswith(tuple(self.readonly)):
                continue

            for filename in filenames:
                fullName = os.path.realpath(os.path.join(root, filename))
                if not os.path.isfile(fullName):
                    continue

                if '.app' in fullName:
                    indices = [i for i, x in enumerate(rootDirectory.split('/')) if ".app" in x]
                    if len(indices) > 0:
                        appname = '.'.join(rootDirectory.split('/')[indices[-1]].split('.')[:-1])
                        if appname not in applications:
                            applications.append(appname)

                for filecheck in self.results.keys():
                    try:
                        if fullName in self.results[filecheck]["fullpath"]:
                            continue
                    except KeyError:
                        pass

                # Check if file is executable and not an uninteresting file
                if (os.access(fullName, os.X_OK) and os.path.splitext(fullName)[
                    -1].lower() not in self.uninterestingexts) or (os.path.splitext(fullName)[-1].lower() not in self.uninterestingexts and os.path.splitext(fullName)[-1].lower() in self.knownpopscriptexts):
                    # If the files an normally named executable or script add to parsing list and check if current
                    # user context can write to the file

                    if os.path.splitext(fullName)[-1] == '.dyblib' or os.path.splitext(fullName)[-1] == '' or \
                            os.path.splitext(fullName)[-1] in self.knownpopscriptexts or os.path.split(fullName)[-1].startswith(tuple(applications)):
                        self.initializeDictionaryItem(filename, fullName, True)
                        if self.verbose:
                            print("[+] Found executable file: %s" % fullName)
                    # If the file doesn't meet the above criteria save as a potential interesting file to dict.
                    else:
                        self.initializeDictionaryItem(filename, fullName, False)
                        if '.' in filename:
                            self.results[fullName]['filetypeh'] = filename.split('.')[-1]
                        else:
                            self.results[fullName]['filetypeh'] = "Misc"
                        if self.verbose:
                            print("[+] Found interesting file: %s" % fullName)
                # Save the file even if it's not executable to the interesting files list
                elif os.path.splitext(fullName)[-1].lower() not in self.uninterestingexts:
                    self.initializeDictionaryItem(filename, fullName, False)
                    if '.' in filename:
                        self.results[fullName]['filetypeh'] = filename.split('.')[-1]
                    else:
                        self.results[fullName]['filetypeh'] = "Misc"
                    if self.verbose:
                        print("[+] Found interesting file: %s" % fullName)

        if self.verbose:
            print("[+] Finished gathering executable files in %s" % rootDirectory)

    def resolvePath(self, binaryPath, unresolvedPath):
        resolvedPath = unresolvedPath
        unresolvedPath = str(unresolvedPath)

        if self.results[binaryPath]['filetype'] == self.MH_EXECUTE:
            # resolve '@loader_path'
            if unresolvedPath.startswith('@loader_path'):
                resolvedPath = os.path.abspath(
                    os.path.split(binaryPath)[0] + unresolvedPath.replace('@loader_path', ''))
            # resolve '@executable_path'
            elif unresolvedPath.startswith('@executable_path'):
                resolvedPath = os.path.abspath(
                    os.path.split(binaryPath)[0] + unresolvedPath.replace('@executable_path', ''))
        else:
            matchindices = [i for i, x in enumerate(binaryPath.split('/')) if x == unresolvedPath.split('/')[-1]]
            unmatchindicies = [i for i, x in enumerate(binaryPath.split('/')) if x == 'Contents']
            if len(matchindices) > 0:
                if unresolvedPath.startswith('@loader_path'):
                    resolvedPath = os.path.abspath(
                        '/'.join(binaryPath.split('/')[0:matchindices[-1]]) + "/MacOS" + unresolvedPath.replace(
                            '@loader_path', ''))
                elif unresolvedPath.startswith('@executable_path'):
                    resolvedPath = os.path.abspath(
                        '/'.join(binaryPath.split('/')[0:matchindices[-1]]) + "/MacOS" + unresolvedPath.replace(
                            '@executable_path', ''))
            elif len(unmatchindicies) > 0:
                if unresolvedPath.startswith('@loader_path'):
                    resolvedPath = os.path.abspath(
                        '/'.join(binaryPath.split('/')[0:unmatchindicies[-1]]) + "/Contents/MacOS" + unresolvedPath.replace(
                            '@loader_path', ''))
                elif unresolvedPath.startswith('@executable_path'):
                    resolvedPath = os.path.abspath(
                        '/'.join(binaryPath.split('/')[0:unmatchindicies[-1]]) + "/Contents/MacOS" + unresolvedPath.replace(
                            '@executable_path', ''))

        return resolvedPath.rstrip(b'\x00')

    def parseExecutables(self):
        if self.verbose:
            print("[*] Parsing executable files for validity as an executable, script, dylib or bundle")
        for binarypath in self.results.keys():
            binary = self.results[binarypath]["filename"]
            try:
                f = open(binarypath, 'rb')
                if not f:
                    if self.verbose:
                        print("[-] Could not open: %s" % binary)
                    continue
            except:
                if self.verbose:
                    print("[-] Could not open: %s" % binary)
                continue

            # Check if it is an interesting file and not an executable
            if self.results[binarypath]["parse"] is False:
                continue

            # passed checks as an executable create dictionary placeholder for vulnerabilities
            self.results[binarypath]["vulnerable"] = {'DylibHijack': [], 'WeakDylib': [], "BackdoorableScript": []}

            isScript = self.scriptCheck(f, binary, binarypath)
            if isScript:
                if self.verbose:
                    print("[+] Potential backdoor-able script: %s" % binarypath)
                continue



            # check if it's a supported (intel) architecture
            # ->also returns the supported mach-O header
            (isSupported, machoHeader) = self.isSupportedArchitecture(f)
            if not isSupported:
                if self.verbose:
                    print("[-] Either not supported architecture or not a binary: %s" % binary)
                    self.results[binarypath]["parse"] = False
                continue

            # skip binaries that aren't main executables, dylibs or bundles
            if machoHeader.filetype not in [self.MH_EXECUTE, self.MH_DYLIB, self.MH_BUNDLE, self.MH_KEXT_BUNDLE]:
                if self.verbose:
                    print("[-] Not an executable, dylib, bundle, or kext bundle: %s" % binary)
                    self.results[binarypath]["parse"] = False
                continue

            self.results[binarypath]["parse"] = "Started Parse"
            if self.verbose:
                print("[*] Parsing: %s" % binary)
                print("\tFull binary path: %s" % binarypath)

            # init dictionary for process
            self.results[binarypath]["load"] = {'LC_RPATHs': [], 'LC_LOAD_DYLIBs': [], 'LC_LOAD_WEAK_DYLIBs': []}

            # save filetype
            self.results[binarypath]['filetype'] = machoHeader.filetype

            if self.results[binarypath]['filetype'] == self.MH_EXECUTE:
                self.results[binarypath]['filetypeh'] = "Executable"
            elif self.results[binarypath]['filetype'] == self.MH_DYLIB:
                self.results[binarypath]['filetypeh'] = "Dylib"
            elif self.results[binarypath]['filetype'] == self.MH_BUNDLE:
                self.results[binarypath]['filetypeh'] = "Bundle"
            elif self.results[binarypath]['filetype'] == self.MH_KEXT_BUNDLE:
                self.results[binarypath]['filetypeh'] = "KextBundle"
            else:
                self.results[binarypath]['filetypeh'] = "Misc"

            # iterate over all load
            # ->save LC_RPATHs, LC_LOAD_DYLIBs, and LC_LOAD_WEAK_DYLIBs
            if self.CPU_TYPE_NAMES.get(machoHeader.cputype) == 'x86_64':
                f.seek(32, io.SEEK_SET)
            else:
                f.seek(28, io.SEEK_SET)

            for cmd in range(machoHeader.ncmds):
                # handle LC_RPATH's
                # ->resolve and save
                # save offset to load commands
                try:
                    lc = load_command.from_buffer_copy(f.read(self.LC_Header_Sz))
                except Exception as e:
                    break  # break out of the nested loop and continue with the parent loop
                size = lc.cmdsize
                if lc.cmd == self.LC_RPATH:
                    # grab rpath
                    pathoffset = struct.unpack('<L', f.read(4))[0]
                    f.seek(pathoffset - (self.LC_Header_Sz + 4), io.SEEK_CUR)
                    path = f.read(lc.cmdsize - pathoffset)
                    rPathDirectory = path.rstrip(b'\x00')
                    if self.verbose:
                        print("\tOriginal rpath: %s" % rPathDirectory)
                    # always attempt to resolve '@executable_path' and '@loader_path'
                    rPathDirectory = self.resolvePath(binarypath, rPathDirectory)
                    if self.verbose:
                        print("\tSystem resolved rpath: %s" % rPathDirectory)

                    self.results[binarypath]["load"]['LC_RPATHs'].append(rPathDirectory)

                # handle LC_LOAD_DYLIB
                # ->save (as is)
                elif lc.cmd == self.LC_LOAD_DYLIB:
                    # tuple, last member is path to import
                    pathoffset = struct.unpack('<L', f.read(4))[0]
                    # skip over version and compatibility
                    f.seek(pathoffset - (self.LC_Header_Sz + 4), io.SEEK_CUR)
                    path = f.read(size - pathoffset)
                    importedDylib = path.rstrip(b'\x00')
                    if self.verbose:
                        print("\t%s imports dylib: %s" % (binary, importedDylib))

                    self.results[binarypath]["load"]['LC_LOAD_DYLIBs'].append(importedDylib)

                # handle for LC_LOAD_WEAK_DYLIB
                # ->resolve (except for '@rpaths') and save
                elif lc.cmd == self.LC_LOAD_WEAK_DYLIB:
                    # tuple, last member is path to import
                    pathoffset = struct.unpack('<L', f.read(4))[0]

                    # skip over version and compatibility
                    f.seek(pathoffset - (self.LC_Header_Sz + 4), io.SEEK_CUR)
                    path = f.read(size - pathoffset)
                    weakDylib = path.rstrip(b'\x00')

                    # always attempt to resolve '@executable_path' and '@loader_path'
                    weakDylib = self.resolvePath(binarypath, weakDylib)

                    if self.verbose:
                        print("\t%s has a weak dylib: %s" % (binary, weakDylib))

                    self.results[binarypath]["load"]['LC_LOAD_WEAK_DYLIBs'].append(weakDylib)
                else:
                    f.seek(size - self.LC_Header_Sz, io.SEEK_CUR)
            self.results[binarypath]["parse"] = "Complete"
            if self.verbose:
                print("[+] Completed parsing: %s" % binary)

        if self.verbose:
            print("[+] Finished parsing files")

    def vulnerabilityDictInput(self, vulntype, fullpath, hijackpath, loadorder, certainty, contextwriteperm, readonlypartition, indicator, mode):
        ftype = self.results[fullpath]['filetypeh']
        binary = self.results[fullpath]['filename']
        if contextwriteperm:
            context = "Write"
        else:
            context = "Read"
        if readonlypartition and not self.sipdisabled:
            context = "ReadOnly"

        self.results[fullpath]['vulnerable'][vulntype].append(
            {'hijackPath': hijackpath, 'LoadOrder': loadorder, 'Certainty': certainty,
             'WriteAccess': contextwriteperm, 'ReadOnlyPartition': readonlypartition, "Mode": mode})
        if certainty == 'Definite' and context != 'ReadOnly':
            if contextwriteperm:
                indicator = indicator * 3    
            print("[%s] [%s] [%s] [%s] [%s] [%s] %s" % (indicator, ftype, binary, vulntype, certainty, context, hijackpath))
        else:
            if self.verbose:
                if contextwriteperm:
                    indicator = indicator * 3
                print("[%s] [%s] [%s] [%s] [%s] [%s] %s" % (
                indicator, ftype, binary, vulntype, certainty, context, hijackpath))

    def passiveDylibVulnProcessor(self, binarypath, dylib, vulntype):
        mode = "Passive"
        # check the first rpath directory (from LC_RPATHs)
        # ->is the rpath'd import there!?
        for loadorder, rpath in enumerate(self.results[binarypath]['load']['LC_RPATHs']):
            hijackpath = rpath + dylib

            # if not found means this binary is potentailly vulnerable!
            if not os.path.exists(hijackpath):
                # Check if current user context has write permissions to the last existing path and if rpath is in the read only partition
                readonlypartition, contextwriteperm = self.readWriteCheck(hijackpath)

                # Set logic statements for ease of reading
                notreadonly = (not readonlypartition)
                executablefirstloaded = (self.results[binarypath]['filetype'] == self.MH_EXECUTE and loadorder == 0)
                executablenextloaded = (self.results[binarypath]['filetype'] == self.MH_EXECUTE and loadorder < 2)
                allfiletypesfirstloaded = (loadorder == 0)
                allfiletypesnextloaded = (loadorder < 2)

                if (executablefirstloaded and notreadonly) or (executablefirstloaded and self.sipdisabled):
                    certainty = 'Definite'
                    indicator = '!'
                    self.vulnerabilityDictInput(vulntype, binarypath, hijackpath, loadorder, certainty,
                                                contextwriteperm, readonlypartition, indicator, mode)
                elif (executablenextloaded and notreadonly) or (executablenextloaded and self.sipdisabled):
                    certainty = 'High'
                    indicator = '+'
                    self.vulnerabilityDictInput(vulntype, binarypath, hijackpath, loadorder, certainty,
                                                contextwriteperm, readonlypartition, indicator, mode)
                elif (allfiletypesnextloaded and notreadonly) or (allfiletypesnextloaded and self.sipdisabled):
                    certainty = 'Potential'
                    indicator = '+'
                    self.vulnerabilityDictInput(vulntype, binarypath, hijackpath, loadorder, certainty,
                                                contextwriteperm, readonlypartition, indicator, mode)
                elif executablefirstloaded and readonlypartition and not self.sipdisabled:
                    certainty = 'Definite'
                    indicator = '-'
                    self.vulnerabilityDictInput(vulntype, binarypath, hijackpath, loadorder, certainty,
                                                contextwriteperm, readonlypartition, indicator, mode)
                elif allfiletypesfirstloaded and readonlypartition and not self.sipdisabled:
                    certainty = 'High'
                    indicator = '-'
                    self.vulnerabilityDictInput(vulntype, binarypath, hijackpath, loadorder, certainty,
                                                contextwriteperm, readonlypartition, indicator, mode)
                elif allfiletypesnextloaded and readonlypartition and not self.sipdisabled:
                    certainty = 'Potential'
                    indicator = '-'
                    self.vulnerabilityDictInput(vulntype, binarypath, hijackpath, loadorder, certainty,
                                                contextwriteperm, readonlypartition, indicator, mode)
                else:
                    certainty = 'Low'
                    indicator = '-'
                    self.vulnerabilityDictInput(vulntype, binarypath, hijackpath, loadorder, certainty,
                                                contextwriteperm, readonlypartition, indicator, mode)
                continue


    def processBinariesPassive(self):
        mode = "Passive"
        if self.verbose:
            print("[*] Processing results to identify weaknesses")
            print("[ID] [FileType] [FileName] [Vulnerability] [Certainty] [Permission] Directory")
        # scan all parsed binaries
        for binarypath in self.results.keys():
            # grab binary entry
            binary = self.results[binarypath]["filename"]

            # Check if the file was actually parsed
            if self.results[binarypath]["parse"] == "Complete":
                # STEP 1: check for vulnerable @rpath'd imports
                # Note: changed the check for potentials cuz knowledge is power
                # check for primary @rpath'd import that doesn't exist
                if len(self.results[binarypath]['load']['LC_RPATHs']):
                    vulntype = "DylibHijack"
                    # check all @rpath'd imports for the executable
                    # ->if there is one that isn't found in a primary LC_RPATH, the executable is vulnerable :)
                    for importedDylib in self.results[binarypath]['load']['LC_LOAD_DYLIBs']:
                        importedDylib = str(importedDylib)
                        # skip non-@rpath'd imports
                        if not importedDylib.startswith('@rpath'):
                            continue

                        # chop off '@rpath'
                        importedDylib = importedDylib.replace('@rpath', '')

                        # send binary path, dylib, and vulnerablity type and process findings/output
                        self.passiveDylibVulnProcessor(binarypath, importedDylib, vulntype)

                # STEP 2: check for vulnerable weak imports
                # can check all binary types...
                # check binary
                for weakDylib in self.results[binarypath]['load']['LC_LOAD_WEAK_DYLIBs']:
                    weakDylib = str(weakDylib)
                    vulntype = "WeakDylib"
                    # got to resolve weak @rpath'd imports before checking if they exist
                    if weakDylib.startswith('@rpath'):
                        # skip @rpath imports if binary doesn't have any LC_RPATHS
                        if not len(self.results[binarypath]['load']['LC_RPATHs']):
                            continue

                        # chop off '@rpath'
                        weakDylib = weakDylib.replace('@rpath', '')

                        # send binary path, dylib, and vulnerablity type and process findings/output
                        self.passiveDylibVulnProcessor(binarypath, weakDylib, vulntype)

                    # path doesn't need to be resolved
                    # ->check/save those that don't exist
                    elif not os.path.exists(weakDylib):
                        readonlypartition, contextwriteperm = self.readWriteCheck(weakDylib)
                        if self.results[binarypath]['filetype'] == self.MH_EXECUTE:
                            certainty = 'High'
                            indicator = '+'
                            loadorder = 'unknown'
                            self.vulnerabilityDictInput(vulntype, binarypath, weakDylib, loadorder, certainty,
                                                        contextwriteperm, readonlypartition, indicator, mode)
                        else:
                            certainty = 'Potential'
                            indicator = '+'
                            loadorder = 'unknown'
                            self.vulnerabilityDictInput(vulntype, binarypath, weakDylib, loadorder, certainty,
                                                        contextwriteperm, readonlypartition, indicator, mode)
                        continue
        if self.verbose:
            print("[+] Completed weakness identification")

    def processBinariesActive(self):
        def on_timeout(proc, status_dict):
            # Kill process on timeout and note as status_dict['timeout']=True
            status_dict['timeout'] = True
            print("[*] Forced time out")
            proc.kill()

        vulntype = "DylibHijack"
        mode = "Active"

        if self.verbose:
            print("[*] Actively identifying weaknesses")
            print("[ID] [FileType] [FileName] [Vulnerability] [Certainty] [Permission] Directory")
        for binarypath in self.results.keys():
            if self.results[binarypath]["parse"] == "Complete":
                binary = self.results[binarypath]["filename"]
                if self.results[binarypath]['filetype'] == self.MH_EXECUTE:
                    # Set up execution key
                    self.results[binarypath]["execution"] = {'standardoutput': [], 'erroroutput': []}

                    # Since this is active output to console instead of asking for verbose
                    print("[*] Executing %s for 3 seconds" % binary)

                    # Copy standard shell environment
                    hijackenv = os.environ.copy()

                    # Add DYLD_PRINT_RPATHS debugging mode to current Python shell environment
                    hijackenv["DYLD_PRINT_RPATHS"] = "1"

                    # Set timeout dictionary to false before execution
                    status_dict = {'timeout': False}

                    # Open executable
                    proc = subprocess.Popen(binarypath, shell=False, env=hijackenv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                    # Set thread timer to 3 seconds
                    timer = threading.Timer(3, on_timeout, [proc, status_dict])

                    # Start thread timer to timeout after 3 seconds
                    timer.start()

                    # Set process to wait until it is forced to timeout
                    proc.wait()

                    # in case we didn't hit timeout
                    timer.cancel()

                    print("[*] Killed %s process" % binary)

                    # Pull stdout and stderr from killed process
                    result = proc.communicate()

                    if result[0] != '':
                        # Add standard out to binaries dictionary
                        self.results[binarypath]["execution"]['standardoutput'].append(result[0])
                        if self.verbose:
                            print("[*] %s had standard output when executed:" % binary)
                            if len(result[0].split('\n')) > 1:
                                standardoutput = result[0].split('\n')
                                for line in standardoutput:
                                    print("\t%s" % line)
                            else:
                                print("\t" + result[0])

                    if result[1] != '':
                        # Add standard error/debugging messages to binaries dictionary
                        self.results[binarypath]["execution"]['erroroutput'].append(result[0])

                    # Split standard error output and look for RPATH failed expanding, then add to vulnerabilities dict
                    for line in result[1].split('\n'):
                        if 'RPATH failed expanding' in line:
                            # Properly split failed load path and turn into an absolute path for reporting
                            relativepath = line.split('to: ')[-1]
                            hijackpath = os.path.abspath(relativepath)

                            if self.verbose:
                                print("\tOriginal failed rpath: %s" % relativepath)
                                #print("\tAbsolute path: %s" % hijackpath)

                            # Check if current user context has write permissions to the last existing path
                            readonlypartition, contextwriteperm = self.readWriteCheck(hijackpath)

                            if not readonlypartition or self.sipdisabled:
                                certainty = 'Definite'
                                indicator = '+'
                                loadorder = 0
                                self.vulnerabilityDictInput(vulntype, binarypath, hijackpath, loadorder, certainty,
                                                            contextwriteperm, readonlypartition, indicator, mode)
                            else:
                                certainty = 'Definite'
                                indicator = '-'
                                loadorder = 0
                                self.vulnerabilityDictInput(vulntype, binarypath, hijackpath, loadorder, certainty,
                                                            contextwriteperm, readonlypartition, indicator, mode)
        if self.verbose:
            print("[*] Completed active weakness identification")

    def ProcessScriptBackdoors(self):
        mode = "Passive"
        if self.verbose:
            print("[*] Parsing backdoorable script list")
        vulntype = "BackdoorableScript"
        for filepath in self.results.keys():
            # Check if current user context has write permissions
            readonlypartition, contextwriteperm = self.readWriteCheck(filepath)
            contextwriteperm = self.results[filepath]["writeable"]

            if self.results[filepath]["parse"] == "Script" and contextwriteperm:
                certainty = 'Potential'
                indicator = '+'
                loadorder = 0
                self.vulnerabilityDictInput(vulntype, filepath, filepath, loadorder, certainty,
                                            contextwriteperm, readonlypartition, indicator, mode)
            elif self.results[filepath]["parse"] == "Script" and self.verbose:
                certainty = 'Potential'
                indicator = '-'
                loadorder = 0
                self.vulnerabilityDictInput(vulntype, filepath, filepath, loadorder, certainty,
                                            contextwriteperm, readonlypartition, indicator, mode)
        if self.verbose:
            print("[*] Finished listing scripts")

    def ProcessInterestingFiles(self):
        if self.verbose:
            print("[*] Parsing interesting files list")
        for fullpath in self.results.keys():
            file = self.results[fullpath]["filename"]
            if self.results[fullpath]["parse"] is False and self.verbose:
                if '.' in file:
                    filetype = file.split('.')[-1]
                else:
                    filetype = "Misc"
                print("[*] [%s] [%s] [InterestingFile] %s" % (filetype, file, fullpath))
        if self.verbose:
            print("[*] Finished listing files")

    def GetResults(self):
        return self.results


class CSVout:
    def __init__(self, filename, results, sipdisabled):
        if filename.lower().endswith('.csv'):
            self.filename = '.'.join(filename.split('.')[:-1])
        else:
            self.filename = filename

        self.vulnfilename = self.filename + '-vulnerabilities.csv'
        self.interestingfilename = self.filename + '-interesting-files.csv'
        self.results = results
        self.sipdisabled = sipdisabled

        self.QUOTE = '"'
        self.sep = ','

    def csvlinewrite(self, row):
        self.f.write(self.joinline(row) + '\n')

    def closecsv(self):
        self.f.close()
        self.f = None

    def quote(self, value):
        if not isinstance(value, str):
            value = str(value)
        return self.QUOTE + value + self.QUOTE

    def joinline(self, row):
        return self.sep.join([self.quote(value) for value in row])

    def writevulns(self):
        self.f = open(self.vulnfilename, 'w')

        # Needed to sort vulnerabilities by Certainty and if they occur in a read-only partition; also prioritize scripts for Potential certainty
        sortbycertainty = ['Definite', 'High', 'Potential', 'Low']
        if self.sipdisabled:
            sortbysip = [False]
        else:
            sortbysip = [False, True]
        scriptsort = ["Script", "Complete"]

        self.csvlinewrite(['Filename', 'Full path', 'File type', 'Discovery Mode', 'Vulnerability', 'Certainty', 'Read Only Partition (SIP)','Write permission', 'Hijack This Path', 'Dylib Load Order'])
        for sipcheck in sortbysip:
            for certain in sortbycertainty:
                for scriptcheck in scriptsort:
                    for fullpath in self.results.keys():
                        file = self.results[fullpath]['filename']
                        if self.results[fullpath]['parse'] == 'Complete' or self.results[fullpath]['parse'] == 'Script':
                            filetype = self.results[fullpath]['filetypeh']
                            if self.results[fullpath]['parse'] == 'Script':
                                if self.results[fullpath]['parse'] != scriptcheck:
                                    continue
                                scriptinfo = self.results[fullpath]['vulnerable']['BackdoorableScript'][0]
                                vulnerability = "Backdoorable Script"
                                certainty = scriptinfo["Certainty"]
                                if certain != certainty:
                                    continue
                                writeperms = self.results[fullpath]['writeable']
                                sip = scriptinfo["ReadOnlyPartition"]
                                if not self.sipdisabled and sip != sipcheck:
                                    continue
                                hijackpath = "See Full path"
                                loadorder = "Unknown"
                                mode = scriptinfo["Mode"]
                                row = [file, fullpath, filetype, mode, vulnerability, certainty, sip, writeperms, hijackpath, loadorder]
                                self.csvlinewrite(row)
                            elif self.results[fullpath]['parse'] == 'Complete':
                                if self.results[fullpath]['parse'] != scriptcheck:
                                    continue
                                if len(self.results[fullpath]['vulnerable']['DylibHijack']) > 0:
                                    vulnerability = "Dylib Hijack"
                                    for hijackabledylib in self.results[fullpath]['vulnerable']['DylibHijack']:
                                        certainty = hijackabledylib["Certainty"]
                                        if certain != certainty:
                                            continue
                                        writeperms = hijackabledylib["WriteAccess"]
                                        sip = hijackabledylib["ReadOnlyPartition"]
                                        if not self.sipdisabled and sip != sipcheck:
                                            continue
                                        hijackpath = hijackabledylib["hijackPath"]
                                        loadorder = hijackabledylib["LoadOrder"]
                                        mode = hijackabledylib["Mode"]
                                        row = [file, fullpath, filetype, mode, vulnerability, certainty, sip, writeperms, hijackpath, loadorder]
                                        self.csvlinewrite(row)
                                if len(self.results[fullpath]['vulnerable']['WeakDylib']) > 0:
                                    vulnerability = "Weak Dylib"
                                    for hijackabledylib in self.results[fullpath]['vulnerable']['WeakDylib']:
                                        certainty = hijackabledylib["Certainty"]
                                        if certain != certainty:
                                            continue
                                        writeperms = hijackabledylib["WriteAccess"]
                                        sip = hijackabledylib["ReadOnlyPartition"]
                                        if not self.sipdisabled and sip != sipcheck:
                                            continue
                                        hijackpath = hijackabledylib["hijackPath"]
                                        loadorder = hijackabledylib["LoadOrder"]
                                        mode = hijackabledylib["Mode"]
                                        row = [file, fullpath, filetype, mode, vulnerability, certainty, sip, writeperms, hijackpath, loadorder]
                                        self.csvlinewrite(row)

        self.closecsv()
        print('[%s] Created %s' % ('*', self.vulnfilename))

    def writeinterestingfiles(self):
        # Example entry:
        # Filename: {
        #   'writeable': Bool, # indicates whether or not the current user that ran the tool has write permissions on the file
        #   'filetypeh': 'String', # indicates the file type as a string : Executable, Dylib, Bundle, KextBundle, Script, Misc (based on file extension)
        #   'parse': 'String', # indicates if the file was an executable and was parsed for weaknesses
        #   'fullpath': 'String', # full file path to file
        # }
        self.f = open(self.interestingfilename, 'w')
        self.csvlinewrite(['Filename', 'Full path', 'File type', 'Write permission'])
        for fullpath in self.results.keys():
            if self.results[fullpath]['parse'] is False:
                file = self.results[fullpath]['filename']
                if 'filetypeh' in self.results[fullpath].keys():
                    filetype = self.results[fullpath]['filetypeh']
                else:
                    filetype = ""
                writeperms = self.results[fullpath]['writeable']
                row = [file, fullpath, filetype, writeperms]
                self.csvlinewrite(row)

        self.closecsv()
        print('[%s] Created %s' % ('*', self.interestingfilename))

# Class that utilizes system standard output and writes to a file.
# -----------------------------------------------
class Logger(object):
    def __init__(self, filename="Default.log"):
        self.terminal = sys.stdout
        self.log = open(filename, "a")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)


# For standalone use of dyib-hijacker
class Main():
    def __init__(self):
        parser = argparse.ArgumentParser(description='Application Hijack Scanner for macOS')
        typeofsearch = parser.add_mutually_exclusive_group(required=True)
        typeofsearch.add_argument('-r', '--running', action='store_true', help='Check currently running processes')
        typeofsearch.add_argument('-i', '--installed', action='store_true', default=False,
                                  help='Check all installed applications')
        typeofsearch.add_argument('-p', '--application', default=False,
                                  help='Check a specific application i.e. /Application/Safari.app')

        output = parser.add_mutually_exclusive_group(required=False)
        output.add_argument('-oS', '--outputstandard', default=False, help='Outputs standard output to a .log file')
        output.add_argument('-oC', '--outputcsv', default=False, help='Outputs results to a .csv file')
        output.add_argument('-oA', '--outputall', default=False, help='Outputs results to a .csv file and standard log')

        parser.add_argument('-s', '--sipdisabled', default=False, action='store_true',
                            help='Use if SIP is disabled on the system to search typically read-only paths')
        aggression = parser.add_mutually_exclusive_group(required=True)
        aggression.add_argument('-A', '--active', default=False, action='store_true',
                            help='Executes main executable binaries with env var export DYLD_PRINT_RPATHS="1"')
        aggression.add_argument('-P', '--passive', default=False, action='store_true',
                                help='Performs classic Dylib Hijack Scan techniques')
        aggression.add_argument('-b', '--bothchecks', default=False, action='store_true',
                                help='Performs both active and passive checks')
        parser.add_argument('-v', '--verbose', default=False, action='store_true',
                            help='Output in verbose mode while script runs')
        parser.add_argument('-d', '--debug', default=False, action='store_true', help=argparse.SUPPRESS)

        args = parser.parse_args()
        self.verbosity = args.verbose
        self.sipdisabled = args.sipdisabled

        self.running = args.running
        self.installed = args.installed
        self.application = args.application

        self.active = args.active
        self.passive = args.passive
        if args.bothchecks:
            self.active = True
            self.passive = True

        self.debug = args.debug

        self.outputcsv = args.outputcsv
        self.outputstandard = args.outputstandard

        if args.outputall:
            self.outputcsv = args.outputall
            self.outputstandard = args.outputall

        if self.outputstandard:
            self.outputfile = ['log', self.outputstandard]
            sys.stdout = Logger(self.outputfile[1] + '.log')

        

    def execute(self):
        scanner = ExecutableScanner(self.verbosity, self.sipdisabled)
        startTime = datetime.now()

        if self.running is True:
            # get list of loaded binaries
            scanner.loadedBinaries()
        elif self.application:
            # get list of executable files
            scanner.installedBinaries(self.application)
        elif self.installed:
            # get list of executable files on the file-system
            scanner.installedBinaries()

        scanner.parseExecutables()

        if self.passive:
            scanner.processBinariesPassive()
        if self.active:
            scanner.processBinariesActive()
        scanner.ProcessScriptBackdoors()
        scanner.ProcessInterestingFiles()

        print("Scan completed in " + str(datetime.now() - startTime))

        self.results = scanner.GetResults()
        if self.outputcsv:
            csvwrite = CSVout(self.outputcsv, self.results, self.sipdisabled)
            csvwrite.writevulns()
            csvwrite.writeinterestingfiles()
        if self.outputstandard:
            print('[%s] Created %s.log' % ('*', self.outputstandard))
            
    def banner(self):
        solid_pixel = unichr(0x2588) * 2
        light_shade_pixel = unichr(0x2591) * 2
        med_shade_pixel = unichr(0x2592) * 2
        dark_shade_pixel = unichr(0x2593) * 2
        blank_pixel = unichr(0x00A0) * 2

        sp = solid_pixel
        bp = blank_pixel
        lsp = light_shade_pixel
        msp = med_shade_pixel
        dsp = dark_shade_pixel

        canvas_dimensions = [19, 19]

        #build blank canvas
        canvas = [[bp] * canvas_dimensions[0] for i in range(canvas_dimensions[1])]

        fill = [[1, range(4, 14)], 
                [2, [4] + range(14, 16)],
                [3, range(5, 8) + [12, 13, 14, 16]],
                [4, [6, 8, 12, 17]],
                [5, [7, 12, 14, 17]],
                [6, [2, 7, 17]],
                [7, [1, 3, 8, 17] + range(12, 16)],
                [8, [2, 4, 5, 8, 12] + range(15, 17)],
                [9, [1, 3, 6, 7, 13]],
                [10, [2, 14]],
                [11, [3, 4, 14]],
                [12, [5, 14]],
                [13, [6, 7, 13]],
                [14, [8, 9, 11, 12]],
                [15, [8, 10, 11]],
                [16, [7, 12]],
                [17, range(7, 13)]
               ]
        dark = [[2, [5, 9, 10, 11]],
                [6, [14, 15]],
                [7, [9, 10]],
                [9, [2]],
                [10, [3]],
                [11, [9, 10]],
                [12, [8, 11]],
                [13, [8, 12]],
                [15, [9]],
                [16, [8, 9, 10]]
               ]
        medium = [[2, [6, 7, 8, 12, 13]],
                [3, [8, 9, 10, 11, 15]],
                [4, [7, 9, 10, 11, 15]],
                [5, [8, 9, 10, 11, 15]],
                [6, [8, 9, 10, 11, 12, 13]],
                [7, [2, 11]],
                [8, [3, 9, 10, 11]],
                [9, [4, 5, 8, 9, 10, 11, 12]],
                [10, range(4, 14)],
                [11, [5, 6, 7, 8, 11, 12, 13]],
                [12, [6, 7, 9, 10, 12, 13]],
                [13, [9, 10, 11]],
                [14, [10]]
               ]
        light = [[4, [16]],
                [5, [16]],
                [6, [16]],
                [7, [16]],
                [16, [11]]
               ]
        coloring = [fill, dark, medium, light]

        # build pixel art
        for indx, type in enumerate(coloring):
            color = bp
            if indx == 0:
                color = sp
            elif indx == 1:
                color = dsp
            elif indx == 2:
                color = msp
            elif indx == 3:
                color = lsp
            for coords in type:
                y = coords[0]
                for x in coords[1]:
                    canvas[x][y] = color


        # add signature and tool name
        center = len(canvas) / 2
        toolname = u"boko.py"
        tooldescription = u"Application Hijack Scanner for macOS"
        signature = u"Jesse Nebling (@bashexplode)"
        canvas[canvas_dimensions[0] - 1][center] += toolname
        canvas[canvas_dimensions[0] - 1][center + 1] += tooldescription
        canvas[canvas_dimensions[0] - 1][center + 3] += signature

        # print canvas
        for y in range(len(canvas)):
            for x in range(len(canvas[y])):
                print(canvas[x][y].encode('utf-8'), end='')
            print()


if __name__ == "__main__":
    try:
        standalone = True
        scan = Main()
        scan.banner()
        scan.execute()
    except KeyboardInterrupt:
        print("You killed it.")
        sys.exit()
