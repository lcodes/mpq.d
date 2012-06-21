#!/usr/bin/rdmd -unittest -debug=MpqTrace

module mpqtest;

import mpq;
import std.stdio : writeln;

void main() {
    auto archive = new MpqArchive("/Applications/World of Warcraft/Data/art.MPQ");
    auto listfile = archive.openFile("(listfile)");
    writeln(cast(char[]) listfile.read());
}

