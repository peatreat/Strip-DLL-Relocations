#include <windows.h>
#include <DbgHelp.h>
#include <filesystem>
#include <iostream>
#include <fstream>

#include <json.h>
#pragma comment(lib, "json.lib")

#pragma comment(lib, "Dbghelp.lib")

void* RvaToPointer(ULONG RVA, PVOID BaseAddress)
{
	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)BaseAddress;
	PIMAGE_NT_HEADERS ImageNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)BaseAddress + pIDH->e_lfanew);
	if (ImageNtHeaders == 0)
		return 0;
	void* va = ::ImageRvaToVa(ImageNtHeaders, BaseAddress, RVA, 0);
	return va;
}

bool ExportHeaders(Json::Value &event, std::string dll_name, PIMAGE_DOS_HEADER dll, bool is_64) {
	PIMAGE_NT_HEADERS nt_headers = nullptr;
	PIMAGE_NT_HEADERS32 nt_headers32 = nullptr;

	if (is_64) {
		nt_headers = (PIMAGE_NT_HEADERS)((LPBYTE)dll + dll->e_lfanew);

		event["ntheader"]["Signature"] = (int)nt_headers->Signature;

		event["ntheader"]["FileHeader"]["Characteristics"] = (int)nt_headers->FileHeader.Characteristics;
		event["ntheader"]["FileHeader"]["Machine"] = (int)nt_headers->FileHeader.Machine;
		event["ntheader"]["FileHeader"]["NumberOfSections"] = (int)nt_headers->FileHeader.NumberOfSections;
		event["ntheader"]["FileHeader"]["TimeDateStamp"] = (int)nt_headers->FileHeader.TimeDateStamp;
		event["ntheader"]["FileHeader"]["PointerToSymbolTable"] = (int)nt_headers->FileHeader.PointerToSymbolTable;
		event["ntheader"]["FileHeader"]["NumberOfSymbols"] = (int)nt_headers->FileHeader.NumberOfSymbols;
		event["ntheader"]["FileHeader"]["SizeOfOptionalHeader"] = (int)nt_headers->FileHeader.SizeOfOptionalHeader;

		event["ntheader"]["OptionalHeader"]["Magic"] = (int)nt_headers->OptionalHeader.Magic;
		event["ntheader"]["OptionalHeader"]["MajorLinkerVersion"] = (int)nt_headers->OptionalHeader.MajorLinkerVersion;
		event["ntheader"]["OptionalHeader"]["MinorLinkerVersion"] = (int)nt_headers->OptionalHeader.MinorLinkerVersion;
		event["ntheader"]["OptionalHeader"]["SizeOfCode"] = (int)nt_headers->OptionalHeader.SizeOfCode;
		event["ntheader"]["OptionalHeader"]["SizeOfInitializedData"] = (int)nt_headers->OptionalHeader.SizeOfInitializedData;
		event["ntheader"]["OptionalHeader"]["SizeOfUninitializedData"] = (int)nt_headers->OptionalHeader.SizeOfUninitializedData;
		event["ntheader"]["OptionalHeader"]["AddressOfEntryPoint"] = (int)nt_headers->OptionalHeader.AddressOfEntryPoint;
		event["ntheader"]["OptionalHeader"]["BaseOfCode"] = (int)nt_headers->OptionalHeader.BaseOfCode;

		event["ntheader"]["OptionalHeader"]["ImageBase"] = (int)nt_headers->OptionalHeader.ImageBase;
		event["ntheader"]["OptionalHeader"]["SectionAlignment"] = (int)nt_headers->OptionalHeader.SectionAlignment;
		event["ntheader"]["OptionalHeader"]["FileAlignment"] = (int)nt_headers->OptionalHeader.FileAlignment;
		event["ntheader"]["OptionalHeader"]["MajorOperatingSystemVersion"] = (int)nt_headers->OptionalHeader.MajorOperatingSystemVersion;
		event["ntheader"]["OptionalHeader"]["MinorOperatingSystemVersion"] = (int)nt_headers->OptionalHeader.MinorOperatingSystemVersion;
		event["ntheader"]["OptionalHeader"]["MajorImageVersion"] = (int)nt_headers->OptionalHeader.MajorImageVersion;
		event["ntheader"]["OptionalHeader"]["MinorImageVersion"] = (int)nt_headers->OptionalHeader.MinorImageVersion;
		event["ntheader"]["OptionalHeader"]["MajorSubsystemVersion"] = (int)nt_headers->OptionalHeader.MajorSubsystemVersion;
		event["ntheader"]["OptionalHeader"]["MinorSubsystemVersion"] = (int)nt_headers->OptionalHeader.MinorSubsystemVersion;
		event["ntheader"]["OptionalHeader"]["Win32VersionValue"] = (int)nt_headers->OptionalHeader.Win32VersionValue;
		event["ntheader"]["OptionalHeader"]["SizeOfImage"] = (int)nt_headers->OptionalHeader.SizeOfImage;
		event["ntheader"]["OptionalHeader"]["SizeOfHeaders"] = (int)nt_headers->OptionalHeader.SizeOfHeaders;
		event["ntheader"]["OptionalHeader"]["CheckSum"] = (int)nt_headers->OptionalHeader.CheckSum;
		event["ntheader"]["OptionalHeader"]["Subsystem"] = (int)nt_headers->OptionalHeader.Subsystem;
		event["ntheader"]["OptionalHeader"]["DllCharacteristics"] = (int)nt_headers->OptionalHeader.DllCharacteristics;
		event["ntheader"]["OptionalHeader"]["SizeOfStackReserve"] = (int)nt_headers->OptionalHeader.SizeOfStackReserve;
		event["ntheader"]["OptionalHeader"]["SizeOfStackCommit"] = (int)nt_headers->OptionalHeader.SizeOfStackCommit;
		event["ntheader"]["OptionalHeader"]["SizeOfHeapReserve"] = (int)nt_headers->OptionalHeader.SizeOfHeapReserve;
		event["ntheader"]["OptionalHeader"]["SizeOfHeapCommit"] = (int)nt_headers->OptionalHeader.SizeOfHeapCommit;
		event["ntheader"]["OptionalHeader"]["LoaderFlags"] = (int)nt_headers->OptionalHeader.LoaderFlags;
		event["ntheader"]["OptionalHeader"]["NumberOfRvaAndSizes"] = (int)nt_headers->OptionalHeader.NumberOfRvaAndSizes;

		for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
			event["ntheader"]["OptionalHeader"]["DataDirectory"][i]["VirtualAddress"] = (int)nt_headers->OptionalHeader.DataDirectory[i].VirtualAddress;
			event["ntheader"]["OptionalHeader"]["DataDirectory"][i]["Size"] = (int)nt_headers->OptionalHeader.DataDirectory[i].Size;
		}
	}
	else {
		nt_headers32 = (PIMAGE_NT_HEADERS32)((LPBYTE)dll + dll->e_lfanew);

		event["ntheader"]["Signature"] = (int)nt_headers32->Signature;

		event["ntheader"]["FileHeader"]["Characteristics"] = (int)nt_headers32->FileHeader.Characteristics;
		event["ntheader"]["FileHeader"]["Machine"] = (int)nt_headers32->FileHeader.Machine;
		event["ntheader"]["FileHeader"]["NumberOfSections"] = (int)nt_headers32->FileHeader.NumberOfSections;
		event["ntheader"]["FileHeader"]["TimeDateStamp"] = (int)nt_headers32->FileHeader.TimeDateStamp;
		event["ntheader"]["FileHeader"]["PointerToSymbolTable"] = (int)nt_headers32->FileHeader.PointerToSymbolTable;
		event["ntheader"]["FileHeader"]["NumberOfSymbols"] = (int)nt_headers32->FileHeader.NumberOfSymbols;
		event["ntheader"]["FileHeader"]["SizeOfOptionalHeader"] = (int)nt_headers32->FileHeader.SizeOfOptionalHeader;

		event["ntheader"]["OptionalHeader"]["Magic"] = (int)nt_headers32->OptionalHeader.Magic;
		event["ntheader"]["OptionalHeader"]["MajorLinkerVersion"] = (int)nt_headers32->OptionalHeader.MajorLinkerVersion;
		event["ntheader"]["OptionalHeader"]["MinorLinkerVersion"] = (int)nt_headers32->OptionalHeader.MinorLinkerVersion;
		event["ntheader"]["OptionalHeader"]["SizeOfCode"] = (int)nt_headers32->OptionalHeader.SizeOfCode;
		event["ntheader"]["OptionalHeader"]["SizeOfInitializedData"] = (int)nt_headers32->OptionalHeader.SizeOfInitializedData;
		event["ntheader"]["OptionalHeader"]["SizeOfUninitializedData"] = (int)nt_headers32->OptionalHeader.SizeOfUninitializedData;
		event["ntheader"]["OptionalHeader"]["AddressOfEntryPoint"] = (int)nt_headers32->OptionalHeader.AddressOfEntryPoint;
		event["ntheader"]["OptionalHeader"]["BaseOfCode"] = (int)nt_headers32->OptionalHeader.BaseOfCode;
		event["ntheader"]["OptionalHeader"]["BaseOfData"] = (int)nt_headers32->OptionalHeader.BaseOfData;

		event["ntheader"]["OptionalHeader"]["ImageBase"] = (int)nt_headers32->OptionalHeader.ImageBase;
		event["ntheader"]["OptionalHeader"]["SectionAlignment"] = (int)nt_headers32->OptionalHeader.SectionAlignment;
		event["ntheader"]["OptionalHeader"]["FileAlignment"] = (int)nt_headers32->OptionalHeader.FileAlignment;
		event["ntheader"]["OptionalHeader"]["MajorOperatingSystemVersion"] = (int)nt_headers32->OptionalHeader.MajorOperatingSystemVersion;
		event["ntheader"]["OptionalHeader"]["MinorOperatingSystemVersion"] = (int)nt_headers32->OptionalHeader.MinorOperatingSystemVersion;
		event["ntheader"]["OptionalHeader"]["MajorImageVersion"] = (int)nt_headers32->OptionalHeader.MajorImageVersion;
		event["ntheader"]["OptionalHeader"]["MinorImageVersion"] = (int)nt_headers32->OptionalHeader.MinorImageVersion;
		event["ntheader"]["OptionalHeader"]["MajorSubsystemVersion"] = (int)nt_headers32->OptionalHeader.MajorSubsystemVersion;
		event["ntheader"]["OptionalHeader"]["MinorSubsystemVersion"] = (int)nt_headers32->OptionalHeader.MinorSubsystemVersion;
		event["ntheader"]["OptionalHeader"]["Win32VersionValue"] = (int)nt_headers32->OptionalHeader.Win32VersionValue;
		event["ntheader"]["OptionalHeader"]["SizeOfImage"] = (int)nt_headers32->OptionalHeader.SizeOfImage;
		event["ntheader"]["OptionalHeader"]["SizeOfHeaders"] = (int)nt_headers32->OptionalHeader.SizeOfHeaders;
		event["ntheader"]["OptionalHeader"]["CheckSum"] = (int)nt_headers32->OptionalHeader.CheckSum;
		event["ntheader"]["OptionalHeader"]["Subsystem"] = (int)nt_headers32->OptionalHeader.Subsystem;
		event["ntheader"]["OptionalHeader"]["DllCharacteristics"] = (int)nt_headers32->OptionalHeader.DllCharacteristics;
		event["ntheader"]["OptionalHeader"]["SizeOfStackReserve"] = (int)nt_headers32->OptionalHeader.SizeOfStackReserve;
		event["ntheader"]["OptionalHeader"]["SizeOfStackCommit"] = (int)nt_headers32->OptionalHeader.SizeOfStackCommit;
		event["ntheader"]["OptionalHeader"]["SizeOfHeapReserve"] = (int)nt_headers32->OptionalHeader.SizeOfHeapReserve;
		event["ntheader"]["OptionalHeader"]["SizeOfHeapCommit"] = (int)nt_headers32->OptionalHeader.SizeOfHeapCommit;
		event["ntheader"]["OptionalHeader"]["LoaderFlags"] = (int)nt_headers32->OptionalHeader.LoaderFlags;
		event["ntheader"]["OptionalHeader"]["NumberOfRvaAndSizes"] = (int)nt_headers32->OptionalHeader.NumberOfRvaAndSizes;

		for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
			event["ntheader"]["OptionalHeader"]["DataDirectory"][i]["VirtualAddress"] = (int)nt_headers32->OptionalHeader.DataDirectory[i].VirtualAddress;
			event["ntheader"]["OptionalHeader"]["DataDirectory"][i]["Size"] = (int)nt_headers32->OptionalHeader.DataDirectory[i].Size;
		}		
	}

	return true;
}

bool ExportSections(Json::Value &event, std::string dll_name, PIMAGE_DOS_HEADER dll, bool is_64) {
	PIMAGE_NT_HEADERS nt_headers = nullptr;
	PIMAGE_NT_HEADERS32 nt_headers32 = nullptr;

	if (is_64) {
		nt_headers = (PIMAGE_NT_HEADERS)((LPBYTE)dll + dll->e_lfanew);
		
		auto pISH = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&nt_headers->OptionalHeader + nt_headers->FileHeader.SizeOfOptionalHeader);

		for (int c = 0; c < nt_headers->FileHeader.NumberOfSections; c++) {
			if (pISH[c].Characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)) {
				event["sections"][c]["Name"] = (char*)pISH[c].Name;
				event["sections"][c]["Misc"]["PhysicalAddress"] = (int)pISH[c].Misc.PhysicalAddress;
				event["sections"][c]["Misc"]["VirtualSize"] = (int)pISH[c].Misc.VirtualSize;
				event["sections"][c]["VirtualAddress"] = (int)pISH[c].VirtualAddress;
				event["sections"][c]["SizeOfRawData"] = (int)pISH[c].SizeOfRawData;
				event["sections"][c]["PointerToRawData"] = (int)pISH[c].PointerToRawData;
				event["sections"][c]["PointerToRelocations"] = (int)pISH[c].PointerToRelocations;
				event["sections"][c]["PointerToLinenumbers"] = (int)pISH[c].PointerToLinenumbers;
				event["sections"][c]["NumberOfRelocations"] = (int)pISH[c].NumberOfRelocations;
				event["sections"][c]["NumberOfLinenumbers"] = (int)pISH[c].NumberOfLinenumbers;
				event["sections"][c]["Characteristics"] = (int)pISH[c].Characteristics;
			}
		}
	}
	else {
		nt_headers32 = (PIMAGE_NT_HEADERS32)((LPBYTE)dll + dll->e_lfanew);

		auto pISH = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&nt_headers32->OptionalHeader + nt_headers32->FileHeader.SizeOfOptionalHeader);

		for (int c = 0; c < nt_headers32->FileHeader.NumberOfSections; c++) {
			if (pISH[c].Characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)) {			
				event["sections"][c]["Name"] = (char*)pISH[c].Name;
				event["sections"][c]["Misc"]["PhysicalAddress"] = (int)pISH[c].Misc.PhysicalAddress;
				event["sections"][c]["Misc"]["VirtualSize"] = (int)pISH[c].Misc.VirtualSize;
				event["sections"][c]["VirtualAddress"] = (int)pISH[c].VirtualAddress;
				event["sections"][c]["SizeOfRawData"] = (int)pISH[c].SizeOfRawData;
				event["sections"][c]["PointerToRawData"] = (int)pISH[c].PointerToRawData;
				event["sections"][c]["PointerToRelocations"] = (int)pISH[c].PointerToRelocations;
				event["sections"][c]["PointerToLinenumbers"] = (int)pISH[c].PointerToLinenumbers;
				event["sections"][c]["NumberOfRelocations"] = (int)pISH[c].NumberOfRelocations;
				event["sections"][c]["NumberOfLinenumbers"] = (int)pISH[c].NumberOfLinenumbers;
				event["sections"][c]["Characteristics"] = (int)pISH[c].Characteristics;
			}
		}
	}

	return true;
}

bool ExportRelocs(Json::Value &event, std::string dll_name, PIMAGE_DOS_HEADER dll, bool is_64) {
	PIMAGE_NT_HEADERS nt_headers = nullptr;
	PIMAGE_NT_HEADERS32 nt_headers32 = nullptr;

	DWORD RelocationSize = NULL;

	if (is_64) {
		nt_headers = (PIMAGE_NT_HEADERS)((LPBYTE)dll + dll->e_lfanew);

		if (nt_headers->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
			return false;

		RelocationSize = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	}
	else {
		nt_headers32 = (PIMAGE_NT_HEADERS32)((LPBYTE)dll + dll->e_lfanew);

		if (nt_headers32->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
				return false;

		RelocationSize = nt_headers32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	}

	if (RelocationSize)
	{
		PIMAGE_BASE_RELOCATION RelocationDirectory = (PIMAGE_BASE_RELOCATION)RvaToPointer((is_64) ? (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) : (nt_headers32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress), dll);
		if (RelocationDirectory)
		{
			PVOID RelocationEnd = reinterpret_cast<PBYTE>(RelocationDirectory) + RelocationSize;

			int index = 0;

			while (RelocationDirectory < RelocationEnd)
			{
				PBYTE RelocBase = static_cast<PBYTE>(RvaToPointer(RelocationDirectory->VirtualAddress, dll));

				DWORD NumRelocs = (RelocationDirectory->SizeOfBlock - 8) >> 1;

				PWORD RelocationData = reinterpret_cast<PWORD>(RelocationDirectory + 1);

				event["relocs"][index]["reloc_data"] = (int)*RelocationData;
				event["relocs"][index]["num_relocs"] = (int)NumRelocs;
				event["relocs"][index]["reloc_va"] = (int)RelocationDirectory->VirtualAddress;

				int c = 0;
				for (DWORD i = 0; i < NumRelocs; ++i, ++c, ++RelocationData)
					event["relocs"][index]["reloc_data2"][c] = (int)*RelocationData;

				index++;
				RelocationDirectory = reinterpret_cast<PIMAGE_BASE_RELOCATION>(RelocationData);
			}
		}
		else
			return false;
	}
	else
		return false;

	return true;
}

bool ExportImports(Json::Value &event, std::string dll_name, PIMAGE_DOS_HEADER dll, bool is_64) {
	PIMAGE_NT_HEADERS nt_headers = nullptr;
	PIMAGE_NT_HEADERS32 nt_headers32 = nullptr;

	PIMAGE_IMPORT_DESCRIPTOR ImageImportDescriptor = nullptr;

	if (is_64) {
		nt_headers = (PIMAGE_NT_HEADERS)((LPBYTE)dll + dll->e_lfanew);

		ImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)RvaToPointer(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, dll);
	}
	else {
		nt_headers32 = (PIMAGE_NT_HEADERS32)((LPBYTE)dll + dll->e_lfanew);

		ImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)RvaToPointer(nt_headers32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, dll);
	}

	if (ImageImportDescriptor)
	{
		for (int c = 0; ImageImportDescriptor->Name; c++, ImageImportDescriptor++)
		{
			char* dllname = (char*)RvaToPointer(ImageImportDescriptor->Name, dll);

			if (!dllname)
				continue;

			event["imports"][c]["thunk"]["OriginalFirstThunk"] = (int)ImageImportDescriptor->OriginalFirstThunk;
			event["imports"][c]["thunk"]["TimeDateStamp"] = (int)ImageImportDescriptor->TimeDateStamp;
			event["imports"][c]["thunk"]["ForwarderChain"] = (int)ImageImportDescriptor->ForwarderChain;
			event["imports"][c]["thunk"]["Name"] = (int)ImageImportDescriptor->Name;
			event["imports"][c]["thunk"]["FirstThunk"] = (int)ImageImportDescriptor->FirstThunk;

			event["imports"][c]["dependency"] = dllname;

			IMAGE_THUNK_DATA* ImageThunkData64 = NULL;
			IMAGE_THUNK_DATA* ImageFuncData64 = NULL;

			IMAGE_THUNK_DATA32* ImageThunkData = NULL;
			IMAGE_THUNK_DATA32* ImageFuncData = NULL;

			if (is_64) {
				ImageThunkData64 = (IMAGE_THUNK_DATA*)RvaToPointer(((ImageImportDescriptor->OriginalFirstThunk) ? (ImageImportDescriptor->OriginalFirstThunk) : (ImageImportDescriptor->FirstThunk)), dll);
				ImageFuncData64 = (IMAGE_THUNK_DATA*)RvaToPointer(ImageImportDescriptor->FirstThunk, dll);
			}
			else {
				ImageThunkData = (IMAGE_THUNK_DATA32*)RvaToPointer(((ImageImportDescriptor->OriginalFirstThunk) ? (ImageImportDescriptor->OriginalFirstThunk) : (ImageImportDescriptor->FirstThunk)), dll);
				ImageFuncData = (IMAGE_THUNK_DATA32*)RvaToPointer(ImageImportDescriptor->FirstThunk, dll);
			}

			if (is_64) {
				for (int i = 0; ImageThunkData64->u1.AddressOfData; i++, ImageThunkData64++, ImageFuncData64++)
				{
					FARPROC FunctionAddress = NULL;

					if (!(ImageThunkData64->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
						PIMAGE_IMPORT_BY_NAME ImageImportByName = (PIMAGE_IMPORT_BY_NAME)RvaToPointer(*(DWORD*)ImageThunkData64, dll);
						char* NameOfImport = (char*)ImageImportByName->Name;

						event["imports"][c]["functions"][i] = NameOfImport;
					}
				}
			}
			else {
				for (int i = 0; ImageThunkData->u1.AddressOfData; i++, ImageThunkData++, ImageFuncData++)
				{
					ULONG_PTR FunctionAddress = NULL;

					if (!(ImageThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG32)) {
						PIMAGE_IMPORT_BY_NAME ImageImportByName = (PIMAGE_IMPORT_BY_NAME)RvaToPointer(*(DWORD*)ImageThunkData, dll);
						char* NameOfImport = (char*)ImageImportByName->Name;

						event["imports"][c]["functions"][i] = NameOfImport;
					}
				}
			}

			RtlZeroMemory(ImageImportDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR));
		}
		return true;
	}

	return false;
}

int main(int argc, char* argv[]) {
	if (!argv[1])
		return 0;

	std::string dll_path = argv[1];
	std::string dll_name = dll_path.substr(dll_path.find_last_of("//") + 1, dll_path.length());

	std::string dll_no_ext = dll_name.substr(0, dll_name.find_last_of('.'));

	auto hFile = CreateFile(dll_path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return 0;

	DWORD filesize = GetFileSize(hFile, NULL), read;

	void* buffer = VirtualAlloc(NULL, filesize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!buffer)
		return 0;

	if (!ReadFile(hFile, buffer, filesize, &read, NULL)) {
		VirtualFree(buffer, 0, MEM_RELEASE);
		CloseHandle(hFile);
		return 0;
	}

	CloseHandle(hFile);

	bool is_64 = false;

	auto dos = (PIMAGE_DOS_HEADER)buffer;

	auto pFH = (PIMAGE_FILE_HEADER)((LPBYTE)buffer + dos->e_lfanew + sizeof(DWORD));

	if (pFH->SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER64))
		is_64 = true;

	Json::Value event;

	ExportHeaders(event, dll_no_ext, dos, is_64);
	ExportImports(event, dll_no_ext, dos, is_64);
	ExportRelocs(event, dll_no_ext, dos, is_64);

	PIMAGE_NT_HEADERS nt = nullptr;
	PIMAGE_NT_HEADERS32 nt32 = nullptr;

	if (is_64) {
		nt = (PIMAGE_NT_HEADERS)((LPBYTE)buffer + dos->e_lfanew);

		nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
		nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;

		nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
		nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;

		PIMAGE_SECTION_HEADER sect = ((PIMAGE_SECTION_HEADER)((ULONG_PTR)nt + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader));
		for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
			if (std::string((char*)sect[i].Name).find(".reloc") != std::string::npos) {
				RtlZeroMemory(RvaToPointer(sect[i].VirtualAddress, buffer), sect[i].SizeOfRawData);
				RtlZeroMemory(&sect[i], sizeof(IMAGE_SECTION_HEADER));
				//nt->FileHeader.NumberOfSections -= 1;
			}
		}

		nt->FileHeader.Characteristics += IMAGE_FILE_RELOCS_STRIPPED;
	}
	else {
		nt32 = (PIMAGE_NT_HEADERS32)((LPBYTE)buffer + dos->e_lfanew);

		nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
		nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;

		nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
		nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;

		PIMAGE_SECTION_HEADER sect = ((PIMAGE_SECTION_HEADER)((ULONG_PTR)nt32 + FIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader) + nt32->FileHeader.SizeOfOptionalHeader));
		for (int i = 0; i < nt32->FileHeader.NumberOfSections; i++) {
			if (std::string((char*)sect[i].Name).find(".reloc") != std::string::npos) {
				RtlZeroMemory(RvaToPointer(sect[i].VirtualAddress, buffer), sect[i].SizeOfRawData);
				RtlZeroMemory(&sect[i], sizeof(IMAGE_SECTION_HEADER));
				//nt32->FileHeader.NumberOfSections -= 1;
			}
		}

		nt32->FileHeader.Characteristics += IMAGE_FILE_RELOCS_STRIPPED;
	}

	ExportSections(event, dll_no_ext, dos, is_64);

	std::ofstream exp(dll_no_ext + "_parsed.json");
	exp << event;
	exp.close();

	std::ofstream fout;
	fout.open(dll_no_ext + "_stripped.dll", std::ios::binary | std::ios::out);
	fout.write((char*)buffer, filesize);
	fout.close();

	return 0;
}
