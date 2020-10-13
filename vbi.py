import argparse
import logging
import os
import pefile
import re
import shutil
import sys

from dissect import cstruct
from enum import Enum

logging.basicConfig(format='[%(levelname)s] - %(name)s - %(message)s', level=logging.DEBUG)
log = logging.getLogger('vbiparse')

VBI_MAGIC = b'1IBV'

PE_MAGIC = b'\x4D\x5A\x90\x00\x03'

PE_TEXT_SECTION_NAMES = [
    '.text',
    'INIT',
    'POOLCODE',
    'PAGE',
    'PAGEKD',
    'PAGEKRPC',
    'PAGERPCD',
    'PAGEPNP',
    'PAGENPNP',
    'PAGEICES',
    'NONPAGED',
    'PAGEVRFY',
    'PAGEVRF1',
    'PAGEVRF2',
    'PAGEMSG',
    'PAGER0']


class VbiType(Enum):
    Host = 1,
    SRA = 2,
    ERA = 3

    def __str__(self):
        return self.name.lower()

    def __repr__(self):
        return str(self)

    @staticmethod
    def from_str(s):
        try:
            return VbiType[s]
        except KeyError:
            raise ValueError()


cparser = cstruct.cstruct()
cparser.load("""

enum VbiDirectoryType : uint16 {
    VbiDirectoryEnvironment = 0x0,
    VbiDirectoryLoaderBlock = 0x1,
    VbiDirectoryHostDebug = 0x2,
    VbiDirectoryAliasRanges = 0x3,
    VbiDirectoryDebugInfo = 0x4,
    VbiDirectoryDevkitIni = 0x5,
    VbiDirectoryHash = 0x6,
    VbiDirectoryCapabilities = 0x7,
    VbiDirectoryMemorySize = 0x8,
    VbiDirectoryGsCookies = 0x9,
    VbiDirectoryAslr = 0xA,
    VbiDirectoryMemExt = 0xB,
    VbiDirectoryMax = 0xC
};

struct VbiDirectory {
    uint32 Offset;
    uint32 Size;
};

struct VbiHeader {
    uint32 Magic;
    uint32 SizeOfHeaders;
    uint64 BasePhysicalAddress;
    uint32 ImageSize;
    uint32 DataOffset;
    uint64 TrampolineVirtualAddress;
    uint32 StartupCpuCount;
    uint32 DirectoryEntryCount;
    VbiDirectory Directories[12];
};

""")


class VbiFile(object):
    def __init__(self, vbi, vbi_type: VbiType, filename):
        self.header = cparser.VbiHeader(vbi)
        self.directories = self.header.Directories
        self.type = vbi_type
        self.filename = filename

    def get_magic(self) -> int:
        return self.header.Magic

    def get_type(self) -> VbiType:
        return self.type

    def get_size_of_headers(self) -> int:
        return self.header.SizeOfHeaders

    def get_base_physical_addr(self) -> int:
        return self.header.BasePhysicalAddress

    def get_image_size(self) -> int:
        return self.header.ImageSize

    def get_directory_count(self) -> int:
        return self.header.DirectoryEntryCount


class VbiModule(object):
    def __init__(self, file, vbi_type, header_offset, vbi_text_begin: int):
        self.vbi = file
        self.header_offset = header_offset
        self.type = vbi_type
        self.pe = pefile.PE(data=self.get_pe_header())
        self.text_offset_base = vbi_text_begin
        self.data_offset_base = self.get_next_block(self.header_offset + 1536)
        self.file = None
        self.filename = None

    def get_pe_header(self):
        self.vbi.seek(self.header_offset)
        header_buffer = self.vbi.read(1536)
        return header_buffer

    @staticmethod
    def get_next_block(block_offset: int) -> int:
        return (block_offset - 1 | 0xFFF) + 1

    @staticmethod
    def is_code_section(section_name) -> bool:
        return section_name in PE_TEXT_SECTION_NAMES

    def get_filename(self) -> str:
        if hasattr(self.pe, 'FileInfo'):
            for entry in self.pe.FileInfo:
                entry_key = entry[0].Key.decode('ascii')
                if entry_key == 'StringFileInfo':
                    for table in entry[0].StringTable:
                        for item in table.entries.items():
                            item_name = item[0].decode('ascii')
                            if item_name == 'OriginalFilename':
                                item_value = item[1].decode('ascii')
                                return item_value
        else:
            de = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
            self.pe.parse_data_directories(directories=de)
            if not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
                return ''
            return self.pe.DIRECTORY_ENTRY_EXPORT.name.decode('ascii')

    def read_section(self, section, offset):
        vbi_section_offset = self.get_next_block(offset)
        self.data_offset_base = self.get_next_block(vbi_section_offset + section.SizeOfRawData)
        self.file.seek(section.PointerToRawData)
        self.vbi.seek(vbi_section_offset)
        vbi_section_data = bytearray(self.vbi.read(section.SizeOfRawData))
        self.file.write(vbi_section_data)

    def extract(self, directory: str, module_count: int):
        if not os.path.exists(directory):
            os.mkdir(directory)
        if not os.path.exists("tmp"):
            os.mkdir("tmp")

        temp_filename = "module_{}.bin".format(module_count)

        # Write the PE header buffer to export
        self.file = open("{}/{}".format("tmp", temp_filename), "wb")
        self.file.write(bytearray(self.get_pe_header()))

        # Relocate and write each section to export
        log.info("module %s - fetching module sections" % module_count)
        for section in self.pe.sections:
            section_name = section.Name.rstrip(b'\x00').decode('ascii')
            log.info("module %s - reading section %s" % (module_count, section_name))
            if self.is_code_section(section_name):
                self.read_section(section, self.text_offset_base)
            else:
                self.read_section(section, self.data_offset_base)

        # Close the header buffer pe instance
        self.pe.close()

        # Open the corrected file
        self.pe = pefile.PE(self.file.name)

        # Get the original module filename
        if self.type is VbiType["Host"] and module_count == 0:
            self.filename = "hvax64.exe"
        else:
            self.filename = self.get_filename()
            if self.filename is None:
                self.filename = temp_filename

        log.info("module %s - using filename: %s" % (module_count, self.filename))

        self.pe.close()

        target_path = "{}/{}".format(directory, self.filename)
        shutil.copy(self.file.name, target_path)

        log.info("copied %s to %s" % (self.file.name, target_path))

        self.file.close()


def vbi_parse_file(vbi, vbi_type, info):
    try:
        f = open(vbi, "rb")
        with f:
            vbi = VbiFile(f.read(), vbi_type, vbi)
            if info:
                log.info("VBI Magic: %s" % hex(vbi.get_magic()))
                log.info("VBI Size: %s" % hex(vbi.get_image_size()))
                log.info("VBI Base Physical Address: %s" % hex(vbi.get_base_physical_addr()))
                log.info("VBI Directory Count: %s" % vbi.get_directory_count())
                dir_count = 0
                for directory in vbi.directories:
                    log.info(
                        "VBI Directory [%s]:   Offset: %s   Size: %s" % (dir_count, directory.Offset, directory.Size))
                    dir_count += 1

            return vbi

    except IOError:
        log.error("ERROR: Unable to open file: %s" % vbi)


def vbi_extract_modules(vbi, directory: str, vbi_csb: int):
    try:
        f = open(vbi.filename, "rb")
        with f:
            module_count = 0
            regex = re.compile(PE_MAGIC)
            log.info("Locating PE headers...")
            # Use byte pattern of PE to locate valid entries
            for match in regex.finditer(f.read()):
                # TODO: Handle the HV
                if vbi.type is VbiType["Host"] and module_count == 0:
                    module_count += 1
                    continue
                offset = match.start()
                log.info("Found PE entry at: %s" % hex(offset))
                f.seek(offset)

                module = VbiModule(f, vbi.get_type(), offset, vbi_csb)
                module.extract(directory, module_count)

                module_count += 1

    except IOError:
        log.error("ERROR: Unable to open file: %s" % vbi)


def main():
    parser = argparse.ArgumentParser(description='Parse an Xbox VBI')
    parser.add_argument('filename', type=str, help='*.vbi filename')
    parser.add_argument('--info', action='store_true', help='print VBI information')
    parser.add_argument('--type', type=VbiType.from_str, choices=list(VbiType), help='the os target type of VBI')
    parser.add_argument('--extract', action='store_true', help='extract modules from VBI')
    parser.add_argument('--csb', type=lambda x: int(x, 0), help='code section begin offset')
    parser.add_argument('--directory', type=str, help='directory to store extracted files')

    args = parser.parse_args()

    if not os.path.isfile(args.filename):
        log.error("ERROR: %s does not exist" % args.filename)
        sys.exit(-1)

    log.info("VBI File: %s" % args.filename)

    if args.type:
        log.info("VBI Type: %s" % args.type)

    vbi = vbi_parse_file(args.filename, args.type, args.info)

    if args.extract:
        if not args.directory:
            log.error("ERROR: No extraction directory given!")
            sys.exit(-1)
        if not args.csb:
            log.error("ERROR: No starting code section offset given!")
            sys.exit(-1)

        log.info("Extracting files...")
        vbi_extract_modules(vbi, args.directory, args.csb)


if __name__ == '__main__':
    main()
