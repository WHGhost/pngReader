#!/sbin/env python


from sys import argv
from struct import unpack, pack
from zlib import crc32 as crc, decompressobj as decomp
from PIL import Image
from os import system


def main(args=None):

    args = argv[1:] if args == None else args
    valid = "\033[32m\033[01mVALID\033[0m"
    erroned = '\033[31m\033[01mERRONED!\033[0m'
    unknown = "\033[33m\033[01mUNKNOWN!\033[0m"

    try:
        f = open(args[0], 'br')
    except IndexError:
        print("[!]Please specify file name.")
        exit()
    except FileNotFoundError:
        print("[!]The file does not exist.")
        exit()
    except IsADirectoryError:
        print("[!]The given path is a directory, not a file.")
        exit()

    data = 0

    try:
        data = f.read()
    except Exception as e:
        print("[!]Failed to read the file: {}".format(e))
    finally:
        f.close()

    if data == 0:
        exit()

    if read_png_signature(data):
        print("[+]Found PNG signature.")
    else:
        print("[-]The file signature does not match PNG, {}".format(erroned))
        exit()

    chunks = read_chunks(data)

    print("[+]Found {} chunks, here is the report:".format(len(chunks)))

    broken_chunks = []
    valid_chunks = []

    for chunk in chunks:
        crc_valid = chunk.check_crc()
        if crc_valid:
            valid_chunks.append(chunk)
        else:
            broken_chunks.append(chunk)
        print("_" * 50)
        print("From {} to {}".format(chunk.start, chunk.end))
        print("\tChunk type:   {} \t\t{}".format(chunk.type, valid if chunk.isvalidtype() else unknown))
        print("\tData length:  {} \t\t{}".format(chunk.data_length, valid if chunk.type in types and (types[chunk.type] == chunk.data_length or types[chunk.type] == -1) else unknown if not chunk.type in types or types[chunk.type] == -2 else erroned))
        print("\tCRC:          \t\t\t{}".format(valid if crc_valid else erroned))
    print("_" * 50)

    if len(broken_chunks) == 0:
        print("[+]CRC sums look all rigth. {}".format(valid))
    else:
        print("[-]One or more chunks are erroned, see previous report for more details.")

    if len(data) - 1 != chunks[-1].end:
        print("[!]The File does not end at last chunk: {}".format(erroned))

    print("[*]Reading image info from valid chunks.")
    #chunk_no = -1

    ihdr = None

    for chunk in valid_chunks:
        chunkinf = chunk.getChunkInfo()
        print("[*]Reading valid chunk {}".format(chunk))
        if chunk.chunk_no == 0:
            if chunk.type == "IHDR":
                print("[+]Found IHDR chunk first: {}".format(valid))
            else:
                print("[!]{}: The firts chunk should be IHDR and is {}".format(erroned, chunk.type))

        if chunk.chunk_no == len(chunks) - 1:
            if chunk.type == "IEND":
                print("[+]Found IEND chunk last: {}".format(valid))
            else:
                print("[!]{}: The last chunk should be IEND and is {}".format(erroned, chunk.type))

        if chunk.type == "IHDR":
            if not chunk.chunk_no == 0:
                print("[-]Chunk {} should not exist, IHDR should only be at the beggining of the file {}".format(chunk, erroned))
            if not chunkinf.isvalid:
                print("[-]{} seems invalid: {}".format(chunk, erroned))
            else:
                print("[+]{}  seems ok: {}".format(chunk, valid))
            try:
                width = chunkinf.width
            except:
                width = erroned
            try:
                heigth = chunkinf.height
            except:
                heigth = erroned
            try:
                bitdepth = chunkinf.bitdepth
            except:
                bitdepth = -1
            bitvali = bitdepth in chunkinf.valid_bitdepth
            try:
                compression = chunkinf.compression
            except:
                compression = erroned
            try:
                filt = chunkinf.filter
            except:
                filt = erroned
            try:
                interlace = chunkinf.interlace
            except:
                interlace = erroned
            print("\t[*]Image width:              \t{}".format(width))
            print("\t[*]Image height:             \t{}".format(heigth))
            print("\t[*]Image type:               \t{}".format(chunkinf.colortype if chunkinf.colortype != None else erroned))
            print("\t[*]Image bit depth:          \t{}\t{}".format(bitdepth, valid if bitvali else erroned))
            print("\t[*]Image compression method: \t{}\t{}".format(compression, valid if compression in (0, 0) else unknown))
            print("\t[*]Image filtering method:   \t{}\t{}".format(filt, valid if filt in (0, 0) else unknown))
            print("\t[*]Image iterlace method:    \t{}\t{}".format(interlace, valid if filt in (0, 1) else unknown))
            ihdr = chunkinf

        elif chunk.type == 'sRGB':
            if chunkinf.isvalid:
                print("[+]{} seems ok. {}".format(chunk, valid))
            else:
                print("[-]{} seems invalid. {}".format(chunk, erroned))
            try:
                rendering = chunkinf.rendering
            except:
                rendering = erroned
            print("\tRendering itent:             \t{}\t{}".format(rendering, valid if chunkinf.isvalid else unknown))

        elif chunk.type == 'gAMA':
            if chunkinf.isvalid:
                print("[+]{} seems ok. {}".format(chunk, valid))
            else:
                print("[-]{} seems invalid. {}".format(chunk, erroned))
            try:
                gama = chunkinf.gama
            except:
                gama = erroned
            print("\tImage gama:             \t{}".format(gama))

        elif chunk.type == 'pHYs':
            if chunkinf.isvalid:
                print("[+]{} seems ok. {}".format(chunk, valid))
            else:
                print("[-]{} seems invalid. {}".format(chunk, erroned))
            try:
                ppuX = chunkinf.ppuX
            except:
                ppuX = erroned
            try:
                ppuY = chunkinf.ppuY
            except:
                ppuY = erroned
            try:
                unit = chunkinf.unit
            except:
                unit = erroned
            print("\tPixels per X unit:\t{}".format(ppuX))
            print("\tPixels per Y unit:\t{}".format(ppuY))
            print("\tUnit:            \t{}".format("any" if unit==0 else "meter" if unit==1 else "{}:{}".format(unknown,unit)))
            if unit == 1:
                print("\tCalculated dpi:  \t{}x{}".format(round(ppuX / 39.3701), round(ppuY / 39.3701)))

    for chunk in broken_chunks:
        if not chunk.isvalidtype():
            print("[-]{} is of an unknown type, could not attempt to repare it.".format(chunk))
            continue
        print("[*]Checking erroned chunk {}...".format(chunk))
        chunkinf = chunk.getChunkInfo()
        if chunk.type == 'IDAT':
            if ihdr == None:
                print("[-]IHDR isn't ok, can't process IDAT, aborting...")
                continue
            if ihdr.compression != 0:
                print("[-]Unsupported compression, aborting...")
                continue
            print("[*]Trying to decompress erroned IDAT chunk {}".format(chunk))
            undata = chunkinf.decompress()
            if ihdr.interlace != 0:
                print("[-]Unsupported interlace method, aborting...")
                continue
            if ihdr.filter != 0:
                print("[-]Unsupported filter method, aborting...")
                continue



def read_png_signature(data):
    return data[0:8] == b'\x89PNG\r\n\x1a\n'


def read_chunks(data):
    chunks = []
    start = 8
    end = len(data) - 1
    data = data[8:]
    no = -1
    while start <= end:
        no += 1
        length = unpack('>I', data[:4])[0]
        chunk_type = data[4:8]
        chunk_data = data[8:8 + length]
        chunk_crc = data[8 + length: 12 + length]
        chunk = PngChunk(
            data_length=length,
            start=start,
            chunk_type=chunk_type.decode('ascii'),
            data=chunk_data,
            crc=chunk_crc,
            raw_data=data[: start + length],
            chunk_no=no)
        start = start + 12 + length
        data = data[12 + length:]
        chunks.append(chunk)
        if chunk.type == 'IEND':
            break
    return chunks


types ={'IHDR': 13, 'PLTE': -2, 'IDAT':-1, 'IEND': 0, 'tRNS': -2, 'cHRM': -2, 'gAMA': 4, 'iCCP': -2, 'sBIT': -2, 'sRGB': 1, 'tEXt': -2, 'zTXt': -2, 'iTXt': -2, 'bKGD': -2, 'hIST': -2, 'pHYs':9, 'sPLT': -2, 'tIME': -2}


class PngChunk:

    def __init__(self, data_length=-1, start=-1, chunk_type='', raw_type=b'', data=b'', crc=b'', raw_data='', chunk_no=0):
        self.data_length = data_length
        self.start = start
        self.end = (start + 12 + data_length - 1) if start != -1 else -1
        self.type = chunk_type
        self.raw_type = raw_type if raw_type != b'' else chunk_type.encode('ascii')
        self.data = data
        self.raw_data = raw_data
        self.crc = crc
        self.chunk_no = chunk_no

    def __str__(self):
        return "{} from {} to {}".format(self.type, self.start, self.end)
    def check_crc(self):
        return self._compute_crc() == self.crc

    def _compute_crc(self):
        """Copied from pypng: https://github.com/drj11/pypng/blob/master/LICENCE"""
        verify = crc(self.raw_type)
        verify = crc(self.data, verify)
        # Whether the output from zlib.crc32 is signed or not varies
        # according to hideous implementation details, see
        # http://bugs.python.org/issue1202 .
        # We coerce it to be positive here (in a way which works on
        # Python 2.3 and older).
        verify &= 2**32 - 1
        verify = pack('!I', verify)
        return verify

    def update_crc(self):
        self.crc = _compute_crc(self.raw_data)

    def isvalidtype(self):
        global types
        return self.type in types

    def getChunkInfo(self):
        if self.type == 'IHDR':
            return InfoIHDR(self)
        elif self.type == 'sRGB':
            return InfosRGB(self)
        elif self.type == 'gAMA':
            return InfogAMA(self)
        elif self.type == 'pHYs':
            return InfopHYs(self)
        elif self.type == 'IDAT':
            return InfoIDAT(self)


class ChunkInfo:

    def __init__(self, chunk):
        self.chunk = chunk


class InfoIHDR(ChunkInfo):

    def __init__(self, chunk):
        try:
            super(InfoIHDR, self).__init__(chunk)
            self.width = unpack('>I', chunk.data[0:4])[0]
            self.height = unpack('>I', chunk.data[4:8])[0]
            col = self._interpretcolortpe(unpack('B', chunk.data[9:10])[0])
            self.colortype = col[0]
            self.valid_bitdepth = col[1]
            self.bitdepth = unpack('B', chunk.data[8:9])[0]
            self.compression = unpack('B', chunk.data[10:11])[0]
            self.filter = unpack('B', chunk.data[11:12])[0]
            self.interlace = unpack('B', chunk.data[12:13])[0]
            self.isvalid = col[1] != None and self.bitdepth in col[1]
        except Exception as e:
            print(e)
            self.isvalid = False

    def _interpretcolortpe(self, c):
        try:
            ct = (
            ("Greyscale", (1,2, 4, 8, 16)),
            ("Wrong!!", None),
            ("Truecolour", (8, 16)),
            ("Indexed-colour", (1, 2, 4, 8)),
            ("Greyscale with alpha", (8, 16)),
            ("Wrong!!", None),
            ("Truecolour with alpha", (8, 16))
            )
            return ct[c]
        except:
            return None


class InfosRGB(ChunkInfo):

    def __init__(self, chunk):
        try:
            super(InfosRGB, self).__init__(chunk)
            self.rederingtypes = (
                "Perceptual",
                "Relative colorimetric",
                "Saturation",
                "Absolute colorimetric"
            )
            self.rendering = chunk.data[0]
            self.isvalid = self.rendering in range(4)
            if self.isvalid:
                self.rendering = self.rederingtypes[self.rendering]
        except Exception as e:
            print(e)
            self.isvalid = False


class InfogAMA(ChunkInfo):

    def __init__(self, chunk):
        try:
            super(InfogAMA, self).__init__(chunk)
            self.gama = unpack('>I', chunk.data[0:4])[0] / 100000
            self.isvalid = True
        except Exception as e:
            print(e)
            self.isvalid = False

class InfopHYs(ChunkInfo):

    def __init__(self, chunk):
        try:
            super(InfopHYs, self).__init__(chunk)
            self.ppuX = unpack('>I', chunk.data[0:4])[0] #FIXME
            self.ppuY = unpack('>I', chunk.data[4:8])[0]
            self.unit = chunk.data[8]
            self.isvalid = True
        except Exception as e:
            print(e)
            self.isvalid = False

class InfoIDAT(ChunkInfo):

    def __init__(self, chunk):
        super(InfoIDAT, self).__init__(chunk)

    def decompress(self):
        return decomp().decompress(self.chunk.data)


if __name__ == '__main__':
    main()
