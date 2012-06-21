// -*- mode: D; tab-width: 4; fill-column: 120; comment-column: 32; -*-

// Written in the D Programming Language.


/**
 * Single-module library to work with Blizzard Entertainment's MoPaQ archive file format. Tested with DMD 2.059.
 *
 * This module provides three high-level classes called $(D_PSYMBOL MpqFileSystem), $(D_PSYMBOL MpqArchive) and
 * $(D_PSYMBOL MpqFile) used to work with MPQ archives and their contents. The filesystem class provides a facade to a
 * collection of archives. The archives perform the lookups while the files perform the actual extraction. 
 * 
 * This module also provides two lazily evaluated iteration constructs to consume data as needed: a
 * $(MpqDataInputStream) class implementing $(D_PSYMBOL std.stream.Stream) as well as $(MpqDataRange) struct matching
 * the requirements of $(D_PSYMBOL std.range.isInputRange). TODO: they aren't actually implemented yet.
 * 
 * Finally, the full MPQ format is described in the low-level structures and constants. 
 * 
 * Example:
 * This example opens a single MPQ archive and extracts a file.
 * 
 * ---
 * import mpq;
 * import std.stdio;
 *
 * void main() {
 *     auto archive = new MpqArchive("/path/to/file.mpq"); // Open the MPQ archive.
 *     auto listfile = archive.openFile("(listfile)");     // Open the special listfile.
 *     writeln(cast(string) listfile.read());              // Read it into standard output.
 * }
 * ---
 *
 *
 * References: $(LINK http://www.zezula.net/en/mpq/mpqformat.html),
 *             $(LINK https://github.com/ge0rg/libmpq).
 * 
 * License:    $(LINK2 http://www.boost.org/LICENSE_1_0.txt, Boost License 1.0).
 * 
 * Authors:    $(EMAIL Jeremie Pelletier, jeremiep@gmail.com).
 * 
 * History:    06-20-2012 - Version 0.1 able to read files only.
 *                        - New HET and BET tables not supported.
 *                        - File encryption not supported.
 *                        - ZLib compression supported.
 *                        - Embedded user data recognized, reading not supported.
 */
module mpq;


// Build configuration
// =====================================================================================================================

version = MpqUserData;          /// Enable support for embedded used data.
//version = MpqNewTables;         /// Enable support for the new HET and BET tables.
version = MpqOldTables;         /// Enable support for the old hash and block tables.
version = MpqPreferNewTables;   /// Ignore old lookup tables when new ones are present.

//debug = MpqTrace;               /// Enable debugging traces.


// Dependencies
// =====================================================================================================================

import std.algorithm : find;
import std.array     : back, popBack;
import std.ascii     : toUpper;
import std.exception : enforce;
import std.range     : ElementType, isInputRange, retro;
import std.stream    : File, FileMode, SeekPos, Stream;

import etc.c.zlib;

debug(MpqTrace) {
    import std.stdio : writefln, writeln;
}


// Generic Helpers
// =====================================================================================================================

/**
 * Creates a FourCC code from the given $(D_PARAM cc) string.
 *
 * See_Also: $(LINK http://en.wikipedia.org/wiki/FourCC)
 */
@safe uint makeFourCC(string cc) pure nothrow
in { assert(cc.length == 4); }
body {
    uint r;
    foreach(i, c; cc) r |= c << (i * 8);
    return r;
}

version(unittest) static assert(makeFourCC("\x11\x22\x33\x44") == 0x44332211);


/**
 * Returns a 64-bit offset from the given low and high 32-bit components.
 */
@safe ulong toOffset64(uint lo, uint hi) pure nothrow { return cast(ulong) lo | (cast(ulong) hi << 32); }

version(unittest) static assert(toOffset64(0x12345678, 0x09ABCDEF) == 0x09ABCDEF12345678);


// Mpq File System
// =====================================================================================================================

/**
 * Handles a collection of *.mpq archives. Provides a facade to perform file lookups into multiple archives with support
 * for patch archives.
 */
class MpqFileSystem {
    // TODO
}


// Mpq Archive
// =====================================================================================================================

/**
 * Handles a single *.mpq archive file.
 *
 * The user data header, file header as well as lookup tables are loaded when the object is created.
 */
class MpqArchive {
    /**
     * Constructs the object by opening the archive specified by $(D_PARAM fileName).
     *
     * An optional $(D_PARAM archiveOffset) can be specified for embedded mpq archives. A value of -1 means the header
     * needs to be scanned.
     */
    @safe this(string fileName, size_t archiveOffset = 0)
    body { this(fileName, new File(fileName, FileMode.In)); }
    
    /**
     * Constructs the object by using the given archive $(D_PARAM stream).
     */
    @safe this(string fileName, Stream stream) { this(fileName, stream, 0); }

    /**
     * Constructs the object by using the given archive $(D_PARAM stream).
     */
    private @trusted this(string fileName, Stream stream, size_t archiveOffset)
    in {
        assert(fileName.length);
        assert(stream);
        assert(archiveOffset == -1 || archiveOffset % 0x200 == 0);
        assert(stream.readable && stream.seekable);
    }
    body {
        debug(MpqTrace) writefln("Opening MPQ file %s.", fileName);

        _fileName = fileName;
        _file = stream;
        
        readSections(archiveOffset);
        readTables();
    }

    // Destructor for debugging trace.
    debug(MpqTrace) @trusted ~this() { writefln("Closing MPQ file %s.", _fileName); }


    /**
     * Returns the MpqFile object corresponding to the given $(D_PARAM fileName).
     */
    @trusted MpqFile openFile(string fileName)
    in { assert(fileName.length); }
    body {
        version(MpqNewTables) {
            if(_hetTable.signature) {
                assert(0, "TODO");
            }
            else version(MpqOldTables) {}
            else enforce(0, "No support for old MPQ tables.");
        }

        version(MpqOldTables) {
            if(_hashTable.length) {
                auto hash = getHashByName(fileName);
                if(auto file = hash.blockIndex in _openedFiles) return *file;
                return _openedFiles[hash.blockIndex] = new MpqFile(this, fileName, hash);
            }
            else version(MpqNewTables) { enforce(0, "No MPQ lookup tables."); }
            else enforce(0, "No support for new MPQ tables.");
        }

        assert(0);
    }

    
private:
    

    // MPQ Sections
    // =================================================================================================================
    
    /**
     * Reads the userdata and header sections of the MPQ file.
     */
    @trusted void readSections(size_t archiveOffset) {
        size_t realArchiveOffset;
        uint signature;
        bool search, foundUserData;
        
        if(archiveOffset == -1) {
            archiveOffset = 0;
            search = true;
        }

        while(true) {
            debug(MpqTrace) if(search) writefln("Looking for MPQ section at offset %#X.", archiveOffset);

            seek(archiveOffset);
            _file.read(signature);

            // First section found sets the archive offset.
            version(MpqUserData) if(signature == MpqSignature.UserData) {
                enforce(!foundUserData, "More than one MPQ userdata header.");
                foundUserData = true;
                readUserData(archiveOffset);
                realArchiveOffset = archiveOffset;
                archiveOffset = _userData.headerOffset;
                continue;
            }

            if(signature == MpqSignature.FileHeader) {
                readFileHeader(archiveOffset);
                if(realArchiveOffset == 0) realArchiveOffset = archiveOffset;
                break;
            }

            // Keep looking at the next offset unless archiveOffset wasn't -1.
            enforce(search, "Not a valid MPQ archive.");
            archiveOffset += 0x200;
        }

        _archiveOffset = realArchiveOffset;
    }

    
    /**
     * Reads the MPQ user data.
     */
    version(MpqUserData) @trusted void readUserData(size_t offset) {
        debug(MpqTrace) writefln("Reading MPQ user data at offset %#X.", offset);

        // Read and validate the header.
        seek(offset);
        _file.readExact(&_userData, MpqUserData.sizeof);
        enforce(_userData.signature == MpqSignature.UserData, "Expecting MPQ user data signature.");
        enforce(_userData.headerSize == MpqUserData.sizeof, "Wrong MPQ user data header size.");

        // TODO: read userdata blob
    }

    
    /**
     * Reads the MPQ archive file header from disk at the given archive relative $(D_PARAM offset).
     */
    @trusted void readFileHeader(size_t offset) {
        debug(MpqTrace) writefln("Reading MPQ file header (offset: %#X).", offset);

        // Read the bytes of the Version 1 header.
        seek(offset);
        _file.readExact(&_header, MpqHeaderSize.V1);

        // Validate the header (? doc says V3 bytes are optional, need to confirm).
        enforce(_header.signature == MpqSignature.FileHeader, "Expecting MPQ file header signature.");

        immutable sizes = [MpqHeaderSize.V1, MpqHeaderSize.V2, MpqHeaderSize.V3, MpqHeaderSize.V4];
        enforce(_header.version_ == 2 ? _header.headerSize >= MpqHeaderSize.V2
                                      : _header.headerSize == sizes[_header.version_],
                "Wrong MPQ file header size.");

        // Read the remaining bytes of the header for Version 2, 3 and 4.
        size_t remaining = _header.headerSize - MpqHeaderSize.V1;
        if(remaining != 0) _file.readExact(cast(void*) &_header + MpqHeaderSize.V1, remaining);

        // Initialize the archive state related to the file header.
        _blockSize = 0x200 << _header.blockSize;
        
        if(_header.version_ == 0) _archiveSize = _header.oldArchiveSize;
        else if(_header.archiveSize != 0) _archiveSize = _header.archiveSize;

        if(_archiveSize == 0) _archiveSize = guessArchiveSize();
        else enforce(_archiveSize == guessArchiveSize(), "Invalid MPQ archive size.");

        debug(MpqTrace) writefln("Found MPQ version %d (archiveSize: %#X, blockSize: %#X, rawChunkSize: %#X).",
                                 _header.version_ + 1, _archiveSize, _blockSize, _header.rawChunkSize);
    }


    /**
     * Returns the archive size determined by its contents.
     */
    @safe ulong guessArchiveSize() {
        if(_header.blockExTableOffset != 0)
            return _header.blockExTableOffset + MpqBlockEx.sizeof * _header.blockTableLength;
        else if(_header.blockTableOffset != 0)
            return toOffset64(_header.blockTableOffset, _header.blockTableOffsetHi) +
                MpqBlock.sizeof * _header.blockTableLength;
        else
            assert(0, "TODO");
    }
    
    
    /**
     * Reads the lookup tables.
     */
    @trusted void readTables() {
        bool ignoreOldTables;

        version(MpqNewTables) {
            if(_header.hetTableOffset != 0 && _header.betTableOffset != 0) {
                version(MpqPreferNewTables) ignoreOldTables = true;
                assert(0, "TODO");
            }
            else version(MpqOldTables) {}
            else enforce(0, "No support for old MPQ lookup tables.");
        }

        version(MpqOldTables) {
            if(!ignoreOldTables && _header.hashTableOffset != 0 && _header.blockTableOffset != 0) {
                auto hashOffset  = toOffset64(_header.hashTableOffset,  _header.hashTableOffsetHi);
                auto blockOffset = toOffset64(_header.blockTableOffset, _header.blockTableOffsetHi);

                readOldTable!"hash"   (blockOffset  - hashOffset,  hashOffset);
                readOldTable!"block"  (_archiveSize - blockOffset, blockOffset);
                readOldTable!"blockEx"(0,                          _header.blockExTableOffset);
            }
            else version(MpqNewTables) {}
            else enforce(0, "No support for new MPQ lookup tables.");
        }
    }

    
    // Old lookup tables (MPQ version 1 & 2).
    // =================================================================================================================
    
    version(MpqOldTables) {
    

    /**
     * Reads and old MPQ table.
     */
    @trusted void readOldTable(string name)(size_t packedSize, ulong offset) {
        // The extended block table needs special care.
        enum isBlockEx = name == "blockEx";
        enum realName  = isBlockEx ? "block" : name;
        
        if(isBlockEx && offset == 0) return;

        // Alias the table-related properties.
        mixin("alias _" ~ name ~ "Table table;");
        alias ElementType!(typeof(table)) Entry;
        auto count = mixin("_header." ~ realName ~ "TableLength");

        // Validate the packed table size.
        auto unpackedSize     = Entry.sizeof * count;
        auto headerPackedSize = mixin("_header." ~ name ~ "TableSize");
        
        if(!isBlockEx)
            enforce(headerPackedSize == 0 || headerPackedSize == packedSize, "Wrong " ~ name ~ " table packed size.");
        
        debug(MpqTrace) writefln("Reading MPQ " ~ name ~ " table "
                                 "(offset: %#X, entries: %#X, unpackedSize: %#X, packedSize: %#X).",
                                 offset, count, unpackedSize, packedSize);

        // Create and read the table, it may be compressed.
        table = new Entry[count];
        seek(offset);
        
        if(packedSize == unpackedSize) _file.readExact(table.ptr, unpackedSize);
        else assert(0, "TODO");

        // Decrypt the table, the extended block table is never encrypted.
        static if(!isBlockEx) mpqDecryptBlock(table, name == "hash" ? MpqCryptKey.HashTable : MpqCryptKey.BlockTable);
    }


    /**
     * Returns a pointer to the hash table entry representing the given $(D_PARAM fileName).
     */
    @trusted const(MpqHash)* getHashByName(string fileName) const {
        auto mask  = _header.hashTableLength - 1;
        auto index = mpqHashString(fileName, MpqHashType.Index);
        auto hashA = mpqHashString(fileName, MpqHashType.HashA);
        auto hashB = mpqHashString(fileName, MpqHashType.HashB);
        
        debug(MpqTrace) writefln("Looking up MPQ resource %s (index: %#08X, hashA: %#08X, hashB: %#08X).",
                                 fileName, index, hashA, hashB);

        index &= mask;
        auto i = index;
        
        while(true) {
            auto e = &_hashTable[i];

            debug(MpqTrace) writefln("Trying MPQ hash %#X (hashA: %#08X, hashB: %#08X, blockIndex: %#X).",
                                     i, e.hashA, e.hashB, e.blockIndex);

            if(e.blockIndex == MpqSpecialHash.Empty) break;

            if(e.hashA == hashA && e.hashB == hashB) {
                enforce(e.blockIndex < _blockTable.length, "Invalid MPQ block index.");
                return e;
            }
            
            if((i = (i + 1) & mask) == index) break;
        }
        enforce(0, "MPQ resource not found.");  assert(0);
    }

        
    /**
     * Returns a pointer to the block table entry for the given $(D_PARAM index).
     */
    @safe const(MpqBlock)* getBlock(uint index) const nothrow { return &_blockTable[index]; }
    
    
    /**
     * Returns the high word of the 64-bit offset to the file described by the given $(D_PARAM blockIndex).
     */
    @trusted ushort getFileOffsetHi(uint blockIndex) const nothrow {
        return usingBlockExTable ? _blockExTable[blockIndex].offsetHi : 0;
    }

    
    } // version(MpqOldTables)


    // New MPQ lookup tables
    // =================================================================================================================

    version(MpqNewTables) {

    } // version(MpqNewTables)
    

    // Helper methods
    // =================================================================================================================
    
    /**
     * Seeks the file input stream to the given $(D_PARAM offset), relative to the $(D_PSYMBOL _archiveOffset).
     */
    @trusted void seek(ulong offset) {
        enforce(offset < _archiveSize || _archiveSize == 0, "MPQ offset violation.");
        
        // Hack until Phobos implements 64-bit seeking for posix platforms.
        // TODO: fool! do it yourself.
        version(Posix) {
            _file.seek(_archiveOffset, SeekPos.Set);
            while(offset > int.max) {
                _file.seek(int.max, SeekPos.Current);
                offset -= int.max;
            }
            _file.seek(offset, SeekPos.Current);
        }
        else _file.seek(offset + _archiveOffset, SeekPos.Set);
    }

    /**
     * Returns how many sectors are needed for a file of the given $(D_PARAM size).
     */
    @safe size_t getSectorCount(size_t size) const nothrow { return (size + _blockSize - 1) / _blockSize; }
    

    // MPQ archive state
    // =================================================================================================================
    
    string          _fileName;      /// Location of the file in the filesystem.
    Stream          _file;          /// Unbuffered file input stream for the MPQ archive.
    ulong           _archiveSize;   /// Size in bytes of the MPQ archive.
    uint            _blockSize;     /// Size in bytes of an unpacked data block.
    ulong           _archiveOffset; /// Offset from the beginning of the file where the archive begins. All seeks are
                                    /// relative to this offset.

    version(MpqUserData) {
        MpqUserData  _userData;     /// User data header, optional.
    }
    
    MpqHeader        _header;       /// The MPQ file header.

    version(MpqNewTables) {
        MpqHetTable  _hetTable;     /// The new HET table header.
        MpqBetTable  _betTable;     /// The new BET table header.
    }

    version(MpqOldTables) {
        MpqHash[]    _hashTable;    /// The old hash table entries.
        MpqBlock[]   _blockTable;   /// The old block table entries.
        MpqBlockEx[] _blockExTable; /// The old extended block table entries. (For 64-bit block offsets.)

        /// Whether the extended block table is used or not.
        @property bool usingBlockExTable() const nothrow { return _blockExTable.length != 0; }
    }

    MpqFile[uint] _openedFiles;     /// Map of opened files by their block index.
}


// MPQ File
// =====================================================================================================================

/**
 * Represents an opened file within a *.mpq file.
 */
class MpqFile {
    /**
     * Constructs the object from the $(D_PARAM archive) it belongs to, along with its $(D_PARAM fileName) and $(D_PARAM
     * hash) table entry.
     *
     * The sectors information is also read from the archive.
     */
    private @trusted this(MpqArchive archive, string fileName, const(MpqHash)* hash) {
        _archive  = archive;
        _fileName = fileName;
        _hash     = hash;
        _block    = _archive.getBlock(hash.blockIndex);
        _offset   = toOffset64(_block.offset, _archive.getFileOffsetHi(hash.blockIndex));
        _flags    = _block.flags;
        _cryptKey = mpqHashString(_fileName[_fileName.retro().find('\\').source.length .. $], MpqHashType.Crypt);
        
        if(flag!(MpqFlag.FixCryptKey)) _cryptKey = (_cryptKey + _block.offset) ^ _block.unpackedSize;

        debug(MpqTrace) writefln("Opening MPQ resource %s "
                                 "(offset: %#X, packedSize: %#X, unpackedSize: %#X, cryptKey: %#08X).",
                                 fileName, _offset, _block.packedSize, _block.unpackedSize, _cryptKey);

        readSectorOffsets();
    }

    // Destructor for debugging trace.
    debug(MpqTrace) @trusted ~this() { writefln("Closing MPQ resource %s.", _fileName); }


    /**
     * Reads the entire file from the archive and returns its contents.
     */
    @trusted ubyte[] read() {
        size_t unpackedOffset;
        size_t packedSize, unpackedSize = _archive._blockSize;
        auto data = new ubyte[_block.unpackedSize];
        auto encrypted = flag!(MpqFlag.Encrypted);
        
        foreach(i, offset; _sectorOffsets) {
            // Get the packed and unpacked sector sizes.
            if(i + 1 == _sectorOffsets.length) {
                packedSize = _block.packedSize - offset;
                unpackedSize = _block.unpackedSize - unpackedOffset;
                enforce(unpackedSize < _archive._blockSize, "Invalid MPQ sector size.");
            }
            else {
                packedSize = _sectorOffsets[i + 1] - offset;
            }

            enforce(packedSize <= unpackedSize, "Invalid MPQ sector size.");
            enforce(offset + packedSize <= _block.packedSize, "Invalid MPQ sector offset.");

            debug(MpqTrace) writefln("Reading MPQ resource sector %d/%d (offset: %#X, packed: %#X, unpacked: %#X).",
                           i, _sectorOffsets.length - 1, offset, packedSize, unpackedSize);
            
            // Read the sector from disk, decrypt it, unpack it.
            auto packed = packedSize != unpackedSize;
            auto target = data[unpackedOffset .. unpackedOffset + unpackedSize];
            _archive.seek(_offset + offset);
            if(!encrypted && !packed) _archive._file.readExact(target.ptr, packedSize);
            else {
                _archive._file.readExact(_buffer.ptr, packedSize);
                if(encrypted) assert(0, "TODO");
                if(packed) unpackSector(target, packedSize);
            }

            unpackedOffset += unpackedSize;
        }
        
        return data;
    }
    
    
private:
    

    /**
     * Returns the encryption/decryption key for the sector at the given archive $(D_PARAM offset).
     */
    @trusted uint getSectorCryptKey(ulong offset) const {
        assert(0, "TODO");
    }
    
    /**
     * Reads the table of sector offsets from disk.
     */
    @trusted void readSectorOffsets() {
        auto n   = flag!(MpqFlag.SingleUnit) ? 1 : _archive.getSectorCount(_block.unpackedSize);
        auto crc = flag!(MpqFlag.SectorCrc);

        debug(MpqTrace) writefln("Reading MPQ sector offsets (sectors: %d, crc: %s).", n - 1, crc ? "yes" : "no");

        // Read the offsets, including the crc.
        if(crc) ++n;
        auto size = uint.sizeof * n;
        _sectorOffsets = new uint[n];
        _archive.seek(_offset);
        _archive._file.readExact(_sectorOffsets.ptr, size);

        // TODO: why is there another ending offset with the same value as the crc.
        // Hack for files which appear not to be encrypted.
        if(_sectorOffsets[0] != size && _sectorOffsets[0] != size + 4) _flags |= MpqFlag.Encrypted;
        
        // Decrypt the offsets if needed.
        if(flag!(MpqFlag.Encrypted)) assert(0, "TODO");
    
        // Validate the crc and remove it from the offsets array.
        if(crc) {
            enforce(_sectorOffsets.back() == _block.packedSize, "MPQ resource crc check failed.");
            _sectorOffsets.popBack();
        }
    }


    /**
     * Unpacks the sector currently in $(D_PSYMBOL _buffer) into the given $(D_PARAM target) buffer.
     */
    void unpackSector(ubyte[] target, size_t packedSize) {
        if(flag!(MpqFlag.Implode)) assert(0, "TODO");
        else if(flag!(MpqFlag.Compress))
            foreach(strategy; mpqPackStrategies)
                if((_buffer[0] & strategy.flag) != 0)
                    return strategy.unpack(_buffer[1 .. packedSize], target);
        enforce(0, "Don't know how to unpack MPQ sector.");
    }


    /**
     * Helper property to test the template flag.
     */
    @safe @property bool flag(MpqFlag f)() const nothrow { return (_flags & f) != 0; }

    
    // MPQ file state
    // =================================================================================================================
    
    MpqArchive       _archive;       /// The MPQ archive containing this file.
    string           _fileName;      /// The name of the file with path information.
    const(MpqHash)*  _hash;          /// Reference to the hash table entry.
    const(MpqBlock)* _block;         /// Reference to the block table entry.
    ulong            _offset;        /// The computed 64-bit offset from the block and extended block tables.
    uint             _flags;         /// Flags describing the storage method.
    uint             _cryptKey;      /// The cryptography key unique to the file.
    uint[]           _sectorOffsets; /// List of offsets to each sector of the file, relative to _offset.

    static ubyte[0x4000] _buffer = void; /// Thread local unpacking buffer.
}


// MPQ Data Input Stream
// =====================================================================================================================

/**
 * TODO
 */
class MpqDataInputStream : Stream {
    
}


// MPQ Data Range
// =====================================================================================================================

/**
 * TODO
 */
struct MpqDataRange {
    MpqDataInputStream stream;  /// The underlying input stream.

    @property bool empty() const nothrow { assert(0, "TODO"); }
    
    @property ubyte front() { assert(0, "TODO"); }
    
    void popFront() { assert(0, "TODO"); }
}

version(unittest) static assert(isInputRange!MpqDataRange);


// MPQ Encryption / Decryption / Hashing
// =====================================================================================================================

/**
 * The cryptography table used by hashing, encryption and decryption functions.
 */
immutable mpqCryptTable = mpqGenerateCryptTable();

@safe uint[] mpqGenerateCryptTable() pure nothrow {
    auto buffer = new uint[0x500];
    uint seed = 0x00100001;
    foreach(index1; 0 .. 0x100) {
        auto index2 = index1;
        foreach(j; 0 .. 5) {
            seed = (seed * 125 + 3) % 0x2AAAAB;
            uint a = (seed & 0xFFFF) << 0x10;

            seed = (seed * 125 + 3) % 0x2AAAAB;
            uint b = seed & 0xFFFF;

            buffer[index2] = a | b;
            index2 += 0x100;
        }
    }
    return buffer;
}

version(unittest) {
    // Assume all entries to be correct if the first few are.
    static assert(mpqCryptTable[0 .. 6] == [0x55C636E2, 0x02BE0170, 0x584B71D4, 0x2984F00E, 0xB682C809, 0x91CF876B]);
}


/**
 * Computes the hash of the given $(D_PARAM key) string using the given hashing $(D_PARAM type).
 */
@safe uint mpqHashString(string key, MpqHashType type) pure nothrow {
    uint seed1 = 0x7FED7FED;
    uint seed2 = 0xEEEEEEEE;
    foreach(c; key) {
        auto d = toUpper(c);
        seed1 = mpqCryptTable[(type << 8) + d] ^ (seed1 + seed2);
        seed2 = d + seed1 + seed2 + (seed2 << 5) + 3;
    }
    return seed1;
}

enum MpqHashType {
    Index   = 0,                /// Hash table index.
    HashA   = 1,                /// Collision hash A.
    HashB   = 2,                /// Collision hash B.
    Crypt   = 3                 /// Encryption / decryption key.
}

version(unittest) {
    static assert(mpqHashString("arr\\units.dat", MpqHashType.Index) == 0xF4E6C69D);
    static assert(mpqHashString("unit\\neutral\\acritter.grp", MpqHashType.Index) == 0xA26067F3);
}


/**
 * Encrypts or decrypts a slice of $(D_PARAM data) in place using the given cryptography $(D_PARAM key). The $(D_PARAM
 * encrypt) template param determines whether encryption or decryption is performed.
 *
 * For convenience, the $(D_PSYMBOL mpqEncryptBlock) and $(D_PSYMBOL mpqDecryptBlock) functions specialize this one.
 */
@trusted void mpqCryptBlock(bool encrypt, T)(T[] data, uint key) nothrow {
    uint seed = 0xEEEEEEEE;
    auto ptr = cast(uint*) data.ptr;
    auto length = (data.length * T.sizeof) >> 2;
    while(length-- > 0) {
        seed += mpqCryptTable[0x400 + (key & 0xFF)];
        auto c = *ptr ^ (key + seed);
        key = ((~key << 0x15) + 0x11111111) | (key >> 0x0B);
        seed = (encrypt ? *ptr : c) + seed + (seed << 5) + 3;
        *ptr++ = c;
    }
}

/// Specialization of $(D_PSYMBOL mpqCryptBlock).
@safe void mpqEncryptBlock(T)(T[] buf, uint seed) nothrow { mpqCryptBlock!true (buf, seed); }
/// ditto.
@safe void mpqDecryptBlock(T)(T[] buf, uint seed) nothrow { mpqCryptBlock!false(buf, seed); }

/// Global cryptography keys.
enum MpqCryptKey {
    HashTable  = mpqHashString("(hash table)", MpqHashType.Crypt),
    BlockTable = mpqHashString("(block table)", MpqHashType.Crypt)
}

version(unittest) {
    // TODO
}


// Compression / Decompression
// =====================================================================================================================

/**
 * Type of a generic unpacking function. It takes an $(D_PARAM input) buffer and unpacks its data into the given
 * $(D_PARAM output) buffer.
 */
alias void function(in ubyte[] input, ubyte[] output) MpqUnpackFunc;

/**
 * Unpacking function using the Huffman algorithm.
 */
void unpackHuffman(in ubyte[] input, ubyte[] output) {
    assert(0, "TODO");
}

/**
 * Unpacking function using the zlib library.
 */
void unpackZLib(in ubyte[] input, ubyte[] output) {
    z_stream z  = void;
    z.next_in   = cast(ubyte*) input.ptr;
    z.avail_in  = cast(uint) input.length;
    z.total_in  = cast(uint) input.length;
    z.next_out  = output.ptr;
    z.avail_out = cast(uint) output.length;
    z.total_out = 0;
    z.zalloc    = null;
    z.zfree     = null;

    int result;
    if((result = inflateInit(&z))       != Z_OK)         zlibError(result);
    if((result = inflate(&z, Z_FINISH)) != Z_STREAM_END) zlibError(result);
    if((result = inflateEnd(&z))        != Z_OK)         zlibError(result);
}

void zlibError(int code) {
    // TODO: switch on code to show err msg.
    throw new Exception("Zlib unpack error.");
}

/**
 * Unpacking function using the PKZIP algorithm.
 */      
void unpackPkZip(in ubyte[] input, ubyte[] output) {
    assert(0, "TODO");
}

/**
 * Unpacking function using the Bzip2 library.
 */      
void unpackBzip2(in ubyte[] input, ubyte[] output) {
    assert(0, "TODO");
}

/**
 * Unpacking function for mono wave files.
 */      
void unpackWaveMono(in ubyte[] input, ubyte[] output) {
    assert(0, "TODO");
}

/**
 * Unpacking function for stereo wave files.
 */      
void unpackWaveStereo(in ubyte[] input, ubyte[] output) {
    assert(0, "TODO");
}

/**
 * Entry within the $(D_PSYMBOL mpqPackStrategies) table.
 */
struct MpqPackStrategy {
    MpqPackFlag   flag;         /// The unpacking flag this strategy corresponds to.
    MpqUnpackFunc unpack;       /// The unpacking function.
}

/// A table of unpacking strategies supported by MPQ archives.
immutable mpqPackStrategies = [MpqPackStrategy(MpqPackFlag.Huffman,    &unpackHuffman),
                               MpqPackStrategy(MpqPackFlag.ZLib,       &unpackZLib),
                               MpqPackStrategy(MpqPackFlag.PkZip,      &unpackPkZip),
                               MpqPackStrategy(MpqPackFlag.Bzip2,      &unpackBzip2),
                               MpqPackStrategy(MpqPackFlag.WaveMono,   &unpackWaveMono),
                               MpqPackStrategy(MpqPackFlag.WaveStereo, &unpackWaveStereo)];


// MPQ Constants
// =====================================================================================================================

/**
 * Signatures of MPQ section headers.
 */
enum MpqSignature : uint {
    FileHeader = makeFourCC("MPQ\x1A"),
    UserData   = makeFourCC("MPQ\x1B"),
    HetTable   = makeFourCC("HET\x1A"),
    BetTable   = makeFourCC("BET\x1A")
}

/**
 * Indicates the locale of a file within a MPQ archive.
 */
enum MpqLocale : ushort {
    Neutral    = 0,
    Chinese    = 0x404,
    Czech      = 0x405,
    German     = 0x407,
    English    = 0x409,
    Spanish    = 0x40A,
    French     = 0x40C,
    Italian    = 0x410,
    Japanese   = 0x411,
    Korean     = 0x412,
    Polish     = 0x415,
    Portuguese = 0x416,
    Russian    = 0x419,
    EnglishUK  = 0x809
}

/**
 * Describes the storage method of a file.
 */
enum MpqFlag : uint {
    Implode      = 0x00000100,  /// File is compressed using PKWARE.
    Compress     = 0x00000200,  /// File is compressed using multiple algorithms.
    Encrypted    = 0x00010000,  /// File is encrypted.
    FixCryptKey  = 0x00020000,  /// The decryption key needs to be altered according to the position of the file in the
                                /// archive.
    PatchFile    = 0x00100000,  /// The file is an incremental patch for an existing file.
    SingleUnit   = 0x01000000,  /// The file is stored as a single unit instead of being divided into sectors.
    DeleteMarker = 0x02000000,  /// Marks the file as deleted.
    SectorCrc    = 0x04000000,  /// The file contains checksums for each sector. Ignored if the file is not compressed
                                /// or imploded.
    FileExists   = 0x80000000   /// Marks the file as existing, undoing $(D_PSYMBOL deleteMarker).
}

/**
 * Describes the compression method of a file.
 */
enum MpqPackFlag : ubyte {
    Huffman      = 0x01,
    ZLib         = 0x02,
    PkZip        = 0x04,
    Bzip2        = 0x10,
    WaveMono     = 0x40,
    WaveStereo   = 0x80
}

/**
 * Magic values for block indexes. Affects the hash table lookups.
 */
enum MpqSpecialHash : uint {
    Empty   = 0xFFFFFFFF,       /// Empty hash table entry. Terminates searches.
    Deleted = 0xFFFFFFFE        /// Hash table entry has been deleted.
}

/**
 * Filenames of special files containing metadata about the MPQ archive.
 */
enum MpqSpecialFile : string {
    Listfile   = "(listfile)",
    Signature  = "(signature)",
    Attributes = "(attributes)"
}


// Mpq File Structures
// =====================================================================================================================

/// A MD5 checksum.
alias ubyte[16] md5_t;

align(1):

/**
 * Section header for the embedded user data.
 */
struct MpqUserData {
    uint signature;             /// The ('MPQ\x1B') signature.
    uint dataSize;              /// Maximum size of the user data.
    uint headerOffset;          /// Offset of the MPQ header, relative to the archive offset.
    uint headerSize;            /// Size of the user data header. (?)
}

/**
 * Section header for the archive.
 *
 * Contains the fields of all four versions of MPQ suppoted. See the $(D_PSYMBOL MpqHeaderSize) enum for the sizes of
 * this header for versions below 4.
 */
struct MpqHeader {
    // Version 1
    uint   signature;           /// The ('MPQ\x1A') signature.
    uint   headerSize;          /// Size of the archive header.
    uint   oldArchiveSize;      /// Size of the archive. Deprecated in version 2.
    ushort version_;            /// 0 = Version 1 (up to Burning Crusade)
                                /// 1 = Version 2 (Burning Crusade and newer)
                                /// 2 = Version 3 (Cataclysm beta or newer)
                                /// 3 = Version 4 (Cataclysm beta or newer)
    ushort blockSize;           /// Power of two exponent specifying the number of 512-byte disk sectors in each logical
                                /// sector in the archive.
    uint   hashTableOffset;     /// Offset to the beginning of the hash table, relative to the archive offset.
    uint   blockTableOffset;    /// Offset to the beginning of the block table, relative to the archive offset.
    uint   hashTableLength;     /// Number of entries in the hash table. Must be a power of two, and must be less than
                                /// 2^16 for v1, or less than 2^20 for v2.
    uint   blockTableLength;    /// Number of entries in the block table.
    // Version 2
    ulong  blockExTableOffset;  /// Offset to the beginning of the extended block table.
    ushort hashTableOffsetHi;   /// High 16 bits of the hash table offset.
    ushort blockTableOffsetHi;  /// High 16 bits of the block table offset.
    // Version 3
    ulong  archiveSize;         /// Size of the MPQ archive.
    ulong  betTableOffset;      /// Offset to the beginning of the BET table.
    ulong  hetTableOffset;      /// Offset to the beginning of the HET table.
    // Version 4
    ulong  hashTableSize;       /// Compressed size of the hash table.
    ulong  blockTableSize;      /// Compressed size of the block table.
    ulong  blockExTableSize;    /// Compressed size of the extended block table.
    ulong  hetTableSize;        /// Compressed size of the HET table.
    ulong  betTableSize;        /// Compressed size of the BET table.
    uint   rawChunkSize;        /// Size of raw data chunks to calculate MD5.
    md5_t  blockTableMd5;       /// MD5 of the block table before decryption.
    md5_t  hashTableMd5;        /// MD5 of the hash table before decryption.
    md5_t  blockTableExMd5;     /// MD5 of the extended block table.
    md5_t  betTableMd5;         /// MD5 of the BET table before decryption.
    md5_t  hetTableMd5;         /// MD5 of the HET table before decryption.
    md5_t  headerMd5;           /// MD5 of the MPQ header excluding this value.
}

/// Sizes of the $(D_PSYMBOL MpqHeader) struct for all supported versions of the MPQ format.
enum MpqHeaderSize {
    V1 = 0x20,
    V2 = 0x2C,
    V3 = 0x44,
    V4 = 0xD0
}

static assert(MpqHeader.blockExTableOffset.offsetof == MpqHeaderSize.V1);
static assert(MpqHeader.archiveSize.offsetof == MpqHeaderSize.V2);
static assert(MpqHeader.hashTableSize.offsetof == MpqHeaderSize.V3);
static assert(MpqHeader.sizeof == MpqHeaderSize.V4);


/**
 * Header of the new optional HET table in version 3. Replaces the hash table.
 */
struct MpqHetTable {
    uint signature;
    uint version_;
    uint tableSize;
    uint maxFileCount;
    uint hashTableSize;
    uint hashEntrySize;
    uint totalIndexSize;
    uint indexSizeExtra;
    uint indexSize;
    uint blockTableSize;
    //byte[hashTableSize] hetHashTable;
}

/**
 * Header of the new optional BET table in version 3. Replaces the block and extended block tables.
 */
struct MpqBetTable {
    uint signature;
    uint version_;
    uint tableSize;
    uint fileCount;
    uint unknown;
    uint tableEntrySize;

    static struct s {
        uint filePos;
        uint fileSize;
        uint cmpSize;
        uint flagIndex;
        uint unknown;
    }
    s index;
    s count;

    uint totalBetHashSize;
    uint betHashSizeExtra;
    uint betHashSize;
    uint betHashArraySize;
    uint flagCount;
    //uint[flagCount] flagsArray.
    // table (tableEntrySize * maxFileCount), round up to 8.
    // array of BET hashes, (maxFileCount).
}

/**
 * An entry within the hash table. Used to lookup files from their filenames.
 *
 * The filename is hashed using $(D_PSYMBOL MpqHashType.Index). The modulo of this hash by the number of entries in
 * the hash table then give the index to the hash entry.
 *
 * In order to handle collisions, the filename is hashed two more times using $(D_PSYMBOL MpqHashType.HashA) and
 * $(D_PSYMBOL MpqHashType.HashB). These hashes are compared against the $(D_PARAM hashA) and $(D_PARAM hashB) members
 * of the hash table entry. In case of collision, the next hash table index is tried.
 *
 * A $(D_PARAM blockIndex) value of $(D_PSYMBOL MpqSpecialHash.Empty) means the entry is unused and that lookups should
 * stop. A $(D_PARAM blockIndex) value of $(D_PSYMBOL MpqSpecialHash.Deleted) means the entry no longer exists but
 * lookups should continue.
 */
struct MpqHash {
    uint      hashA;               /// First hash used in collision detection.
    uint      hashB;               /// Second hash used in collision detection.
    MpqLocale locale;              /// Describes the locale of the file.
    ushort    platform;            /// TODO
    uint      blockIndex;          /// Index of the file in the block and extended block tables.
}

/**
 * An entry within the block table. Used to read files from the archive.
 *
 * If an extended block table is present, the $(D_PARAM offset) needs to be adjusted to 64-bit, see $(D_PSYMBOL
 * MpqBlockEx).
 *
 * Files are stored in sectors within the archive. Each sector once unpacked has a size corresponding to the archive's
 * sector size. The exception is the last sector which is as large as needed.
 *
 * If the file is compressed, the data begins with an array of 32-bit offsets relative to the $(D_PARAM offset) for each
 * of the file's sectors. Each packed sector begins with one byte for the $MD_PSYMBOL MpqPackFlags).
 */
struct MpqBlock {
    uint   offset;              /// 32-bit offset of the file data within the archive.
    uint   packedSize;          /// Compressed size of the file.
    uint   unpackedSize;        /// Uncompressed size of the file.
    uint   flags;               /// Describes the storage method of the file. See $(D_PSYMBOL MpqFlags).
}

/**
 * An entry within the extended block table. This table provides the high bits of the $(D_PSYMBOL MpqBlock.offset) to
 * form a 64-bit offset.
 */
struct MpqBlockEx {
    ushort  offsetHi;           /// High bits of the file offset.
}


/*
 * Boost Software License - Version 1.0 - August 17th, 2003
 * 
 * Permission is hereby granted, free of charge, to any person or organization obtaining a copy of the software and
 * accompanying documentation covered by this license (the "Software") to use, reproduce, display, distribute, execute,
 * and transmit the Software, and to prepare derivative works of the Software, and to permit third-parties to whom the
 * Software is furnished to do so, all subject to the following:
 * 
 * The copyright notices in the Software and this entire statement, including the above license grant, this restriction
 * and the following disclaimer, must be included in all copies of the Software, in whole or in part, and all derivative
 * works of the Software, unless such copies or derivative works are solely in the form of machine-executable object
 * code generated by a source language processor.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
