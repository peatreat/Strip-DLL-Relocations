# Strip-DLL-Relocations

There is an issue where it reduces sections after erasing the .RELOC section, but does not attempt to relocate the address of the segments after the .RELOC section. This will cause an issue where if the DLL had another segment after the .RELOC segment, then that segment will not get written.
