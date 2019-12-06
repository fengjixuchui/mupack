#include "powapack.h"

#include "../logger.h"
#include "../stdafx.h"
#include "../mudlib.h"
#include "fr_pack/_types.hpp"
stubcode stubcode_ptr;
using namespace pe_bliss;

extern "C" unsigned char* compress_fr(unsigned char* in_data, DWORD in_size, DWORD* out_size);

#define Test86MSByte(b) ((b) == 0 || (b) == 0xFF)
size_t x86_filter_enc(BYTE* data, size_t size)
{
	uint32_t state = 0;
	uint32_t ip = 0;
	const BYTE kMaskToAllowedStatus[8] = { 1, 1, 1, 0, 1, 0, 0, 0 };
	const BYTE kMaskToBitNumber[8] = { 0, 1, 2, 2, 3, 3, 3, 3 };
	size_t bufferPos = 0, prevPosT;
	uint32_t prevMask = state & 0x7;
	if (size < 5)
		return 0;
	ip += 5;
	prevPosT = (size_t)0 - 1;
	for (;;)
	{
		BYTE* p = data + bufferPos;
		BYTE* limit = data + size - 4;
		for (; p < limit; p++)
			if ((*p & 0xFE) == 0xE8)
				break;
		bufferPos = (size_t)(p - data);
		if (p >= limit)
			break;
		prevPosT = bufferPos - prevPosT;
		if (prevPosT > 3)
			prevMask = 0;
		else
		{
			prevMask = (prevMask << ((int)prevPosT - 1)) & 0x7;
			if (prevMask != 0)
			{
				BYTE b = p[4 - kMaskToBitNumber[prevMask]];
				if (!kMaskToAllowedStatus[prevMask] || Test86MSByte(b))
				{
					prevPosT = bufferPos;
					prevMask = ((prevMask << 1) & 0x7) | 1;
					bufferPos++;
					continue;
				}
			}
		}
		prevPosT = bufferPos;

		if (Test86MSByte(p[4]))
		{
			uint32_t src = ((uint32_t)p[4] << 24) | ((uint32_t)p[3] << 16) | ((uint32_t)p[2] << 8) | ((uint32_t)p[1]);
			uint32_t dest;
			for (;;)
			{
				BYTE b;
				int index;
				dest = (ip + (uint32_t)bufferPos) + src;
				if (prevMask == 0)
					break;
				index = kMaskToBitNumber[prevMask] * 8;
				b = (BYTE)(dest >> (24 - index));
				if (!Test86MSByte(b))
					break;
				src = dest ^ ((1 << (32 - index)) - 1);
			}
			p[4] = (BYTE)(~(((dest >> 24) & 1) - 1));
			p[3] = (BYTE)(dest >> 16);
			p[2] = (BYTE)(dest >> 8);
			p[1] = (BYTE)dest;
			bufferPos += 5;
		}
		else
		{
			prevMask = ((prevMask << 1) & 0x7) | 1;
			bufferPos++;
		}
	}
	prevPosT = bufferPos - prevPosT;
	state = ((prevPosT > 3) ? 0 : ((prevMask << ((int)prevPosT - 1)) & 0x7));
	return bufferPos;
}

extern sU32 KKrunchyDepacker(sU8* dst, const sU8* src);

int compress_file(TCHAR* filename)
{
	int file_alignment = 512;
	TCHAR log_info[256] = { 0 };

	LogMessage* message = LogMessage::GetSingleton();
	message->DoLogMessage(L"Opening file...", LogMessage::ERR_INFO);
	std::auto_ptr<std::ifstream> file;
	file.reset(new std::ifstream(filename, std::ios::in | std::ios::binary));
	if (!*file)
	{
		//If the file was not opened successfully - notify user and exit with error
		message->DoLogMessage(L"Cannot open file!", LogMessage::ERR_ERROR);
		return 0;
	}

	pe_base image(*file, pe_properties_32(), false);
	file.reset(0); //Close file and free memory

	if (image.is_dotnet())
	{
		message->DoLogMessage(L"Cannot pack .NET assemblies!", LogMessage::ERR_ERROR);
		return 0;
	}
	resource_directory new_root_dir;


	memset(&stubcode_ptr, 0, sizeof(stubcode));
	stubcode_ptr.lock_opcode = 0xf0;
	stubcode_ptr.OriginalImports = image.get_directory_rva(IMAGE_DIRECTORY_ENTRY_IMPORT);
	stubcode_ptr.OriginalImportsSize = image.get_directory_size(IMAGE_DIRECTORY_ENTRY_IMPORT);
	stubcode_ptr.OriginalResources = image.get_directory_rva(IMAGE_DIRECTORY_ENTRY_RESOURCE);
	stubcode_ptr.OriginalResourcesSize = image.get_directory_size(IMAGE_DIRECTORY_ENTRY_RESOURCE);
	stubcode_ptr.OriginalRelocations = image.get_directory_rva(IMAGE_DIRECTORY_ENTRY_BASERELOC);
	stubcode_ptr.OriginalRelocationsSize = image.get_directory_size(IMAGE_DIRECTORY_ENTRY_BASERELOC);
	stubcode_ptr.OriginalLoadConfig = image.get_directory_rva(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);


	//Raw section bytes
	std::string raw_bytes;
	//Current section index
	unsigned long current_section = 0;
	DWORD codeStart = image.get_base_of_code();
	section_list& sections = image.get_image_sections();
/*
	DWORD codeStart = image.get_base_of_code();
	section_list& sections = image.get_image_sections();
	std::string packed_sections_info;
	packed_sections_info.resize(sections.size() * sizeof(compdata));

	for (auto& s : sections)
	{
		size_t size = s.get_size_of_raw_data();
		std::string& out_buf = s.get_raw_data();
		compdata& info
		= reinterpret_cast<compdata&>(packed_sections_info[current_section * sizeof(compdata)]);
		//resources
		if (stubcode_ptr.OriginalResources == s.get_virtual_address())
		{

		}
		else
		{
			//code
			if (codeStart >= s.get_virtual_address() && codeStart < s.get_virtual_address() + size)
			{
				unsigned char* origdata = (unsigned char*)s.get_raw_data().data();
				x86_filter_enc(origdata, size);
				DWORD compressed_size;
				unsigned char* compdata = compress_fr(origdata, size, &compressed_size);
				out_buf.resize(compressed_size);
				out_buf.assign(&compdata[0], &compdata[0] + compressed_size);
				info.clen = compressed_size;
				info.ulen = 0;
				info.nlen = size;
				info.iscode = true;
				info.src = (LPVOID)s.get_virtual_address();

				s.set_size_of_raw_data(compressed_size);
            }
			else
			{
				unsigned char* origdata = (unsigned char*)s.get_raw_data().data();
				DWORD compressed_size;
				unsigned char* compdata = compress_fr(origdata, size, &compressed_size);
				out_buf.resize(compressed_size);
				out_buf.assign(&compdata[0], &compdata[0] + compressed_size);
				info.clen = compressed_size;
				info.ulen = 0;
				info.nlen = size;
				info.iscode = false;
				info.src = (LPVOID)s.get_virtual_address();
				s.set_size_of_raw_data(compressed_size);
			}
		}
		current_section++;
	}

	*/
	
	for(auto &s : sections)
	{

		wsprintf(log_info, L"Copying %s section at 0x%04X.........", s.get_name(), s.get_virtual_address());
		message->DoLogMessage(log_info, LogMessage::ERR_INFO);


		size_t size = s.get_size_of_raw_data();
		size_t aligned_ = s.get_aligned_virtual_size(image.get_section_alignment()) - size;
		if (codeStart >= s.get_virtual_address() && codeStart < s.get_virtual_address() + size)
		{
			//unsigned char* origdata = (unsigned char*)s.get_raw_data().data();
			//x86_filter_enc(origdata, size);
			//stubcode_ptr.code_locsz = size;
		}
		raw_bytes += s.get_raw_data();
		raw_bytes.insert(raw_bytes.end(), aligned_, '\0');
	}
	int datapcksize = raw_bytes.size();
	//New section
	section pak_datasection;
	pak_datasection.set_name("UPAKK1");
	//Available for reading, writing, execution
	pak_datasection.readable(true).writeable(true).executable(true);
	//Reference to section raw data
	std::string& out_buf = pak_datasection.get_raw_data();

	//do compression
	unsigned char* origdata = (unsigned char*)raw_bytes.data();
	DWORD compressed_size;

	wsprintf(log_info, L"Compressing PE sections.........");
	message->DoLogMessage(log_info, LogMessage::ERR_INFO);

	unsigned char *compdata = compress_fr(origdata, datapcksize,&compressed_size);
	out_buf.resize(compressed_size);
	out_buf.assign(&compdata[0], &compdata[0] + compressed_size);
	unsigned char* depack = (unsigned char*)malloc(datapcksize);
	KKrunchyDepacker(depack, compdata);
	if (memcmp(depack, origdata, datapcksize) != 0)
	{
		message->DoLogMessage(L"Packed data not equal!", LogMessage::ERR_ERROR);
	}
	free(depack);
	free(compdata);
	stubcode_ptr.sizeunpacked = raw_bytes.size();
	stubcode_ptr.sizepacked = compressed_size;
	stubcode_ptr.ImageBase = image.get_image_base_32();	

	wsprintf(log_info, L"Compressed sections in 0x%04X bytes...", compressed_size);
	message->DoLogMessage(log_info, LogMessage::ERR_INFO);
	wsprintf(log_info, L"PE imagebase is 0x%04X...", stubcode_ptr.ImageBase);
	message->DoLogMessage(log_info, LogMessage::ERR_INFO);

	std::auto_ptr<tls_info> tls;
	if (image.has_tls())
	{
		wsprintf(log_info, L"Reading TLS info...");
		message->DoLogMessage(log_info, LogMessage::ERR_INFO);
		tls.reset(new tls_info(get_tls_info(image)));
	}
	exported_functions_list exports;
	export_info exports_info;
	if (image.has_exports())
	{
		wsprintf(log_info, L"Reading exports info...");
		message->DoLogMessage(log_info, LogMessage::ERR_INFO);
		exports = get_exported_functions(image, exports_info);
	}
	std::auto_ptr<image_config_info> load_config;
	if (image.has_config())
	{
		wsprintf(log_info, L"Reading load config info...");
		message->DoLogMessage(log_info, LogMessage::ERR_INFO);

		try
		{
			load_config.reset(new image_config_info(get_image_config(image)));
		}
		catch (const pe_exception& e)
		{
			image.remove_directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
			wsprintf(log_info, L"Error reading load config info...");
			message->DoLogMessage(log_info, LogMessage::ERR_ERROR);
		}
	}
	else
	{
		image.remove_directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
	}

	rebuild_resources(&image, &new_root_dir);

	DWORD total_virtual_size = pe_utils::align_up(datapcksize, image.get_section_alignment());
	image.get_image_sections().clear();
	section& packer_datasection = image.add_section(pak_datasection);

	image.set_section_virtual_size(packer_datasection, total_virtual_size);

	//It is necessary to reserve place for
		//original TLS callbacks
		//plus one cell for zero DWORD
	DWORD first_callback_offset = 0;
	int stubcode_size = stubcode_sz();
	//Build PE stub/bootstrap section
	section unpacker_section;
	unpacker_section.set_name("UPAKK2");
	unpacker_section.readable(true).executable(true).writeable(true);
	stubcode_ptr.packed_ptr = pak_datasection.get_virtual_address() + image.get_image_base_32();
	//we have to make some fake data for the unpacker section, duh!
	std::string& unpacker_data = unpacker_section.get_raw_data();
	unpacker_data = "fart";
	section& unpacker_added_section = image.add_section(unpacker_section);

	if (tls.get())
	{
		stubcode_ptr.tls_index = tls->get_index_rva();
		if (!tls->get_tls_callbacks().empty())
			stubcode_ptr.tls_callbackold = tls->get_callbacks_rva();
		int tls_offset = get_bootloadersz() + offsetof(stubcode, tls_index);
		tls->set_index_rva(pe_base::rva_from_section_offset(unpacker_added_section, tls_offset));
	}

	

	unsigned char* stubcode_data = build_stub(image.get_ep(), image.get_image_base_32(), unpacker_added_section.get_virtual_address(), &stubcode_size);
	unpacker_added_section.get_raw_data().resize(stubcode_size);
	unpacker_added_section.get_raw_data() = std::string(reinterpret_cast<const char*>(stubcode_data), stubcode_size);
	free(stubcode_data);

	wsprintf(log_info, L"Building shellcode at 0x%04X, using 0x%04X bytes...", unpacker_added_section.get_virtual_address(),stubcode_size);
	message->DoLogMessage(log_info, LogMessage::ERR_INFO);

	//Build loader imports
	import_library kernel32;
	imported_function func;
	kernel32.set_name("kernel32.dll"); //Set library name
	func.set_name("LoadLibraryA"); //Its name
	kernel32.add_import(func); //Add it to the library
	func.set_name("GetProcAddress");
	kernel32.add_import(func); //Add it, too
	func.set_name("VirtualAlloc");
	kernel32.add_import(func); //Add it, too
	func.set_name("VirtualFree");
	kernel32.add_import(func); //Add it, too
	func.set_name("VirtualProtect");
	kernel32.add_import(func); //Add it, too
	func.set_name("RtlMoveMemory");
	kernel32.add_import(func); //Add it, too
	//Set loader IAT RVA to offset in loader header
	int imports_offset = get_bootloadersz() + offsetof(stubcode, loadlib);

	wsprintf(log_info, L"Building IAT at 0x%04X", imports_offset);
	message->DoLogMessage(log_info, LogMessage::ERR_INFO);


	DWORD load_library_address_rva = pe_base::rva_from_section_offset(unpacker_added_section, imports_offset);
	kernel32.set_rva_to_iat(load_library_address_rva);
	imported_functions_list imports;
	imports.push_back(kernel32);
	import_rebuilder_settings settings;
	//We don't need original import address table (explanations will be given further) 
	settings.build_original_iat(false);
	settings.save_iat_and_original_iat_rvas(true, true);
	//Place imports right after packed data end
	settings.set_offset_from_section_start(unpacker_added_section.get_raw_data().size());
	if (!new_root_dir.get_entry_list().empty())
		settings.enable_auto_strip_last_section(false);
	rebuild_imports(image, imports, unpacker_added_section, settings);


	wsprintf(log_info, L"Building resources.....");
	message->DoLogMessage(log_info, LogMessage::ERR_INFO);

	if (!new_root_dir.get_entry_list().empty())
		rebuild_resources(image, new_root_dir, unpacker_added_section, unpacker_added_section.get_raw_data().size());

	//Set new entry point - now it points to
	//the beginning of unpacker

	
	if (tls.get())
	{
		wsprintf(log_info, L"Rebuilding TLS directory.....");
		message->DoLogMessage(log_info, LogMessage::ERR_INFO);

		//Reference to unpacker raw section data
		//Only unpacker body is located there yet
		std::string& data = unpacker_added_section.get_raw_data();

		//Calculate the position to write IMAGE_TLS_DIRECTORY32 structure
		DWORD directory_pos = data.size();
		//Allocate space for this structure
		//sizeof(DWORD) is required for alignment, because
		//IMAGE_TLS_DIRECTORY32 must be aligned to 4-byte boundary
		data.resize(data.size() + sizeof(IMAGE_TLS_DIRECTORY32) + sizeof(DWORD));

		//If TLS has callbacks...
		if (!tls->get_tls_callbacks().empty())
		{
			wsprintf(log_info, L"Rebuilding TLS callbacks.....");
			message->DoLogMessage(log_info, LogMessage::ERR_INFO);

			//It is necessary to reserve memory
			//for original TLS callback addresses
			//Plus 1 cell for null DWORD
			first_callback_offset = data.size();
			data.resize(data.size() + sizeof(DWORD) * (tls->get_tls_callbacks().size() + 1));

			//First callback will be our empty one (ret 0xC),
			//Write its address
			*reinterpret_cast<DWORD*>(&data[first_callback_offset]) =
				image.rva_to_va_32(pe_base::rva_from_section_offset(unpacker_added_section, 0x07));

			//Write relative virtual address
			//of new TLS callbacks table
			tls->set_callbacks_rva(pe_base::rva_from_section_offset(unpacker_added_section, first_callback_offset));
			//Now write new callbacks table relative address
			//to packed_file_info structure, which is placed at
			//the beginning of first section
			reinterpret_cast<stubcode*>(&image.get_image_sections().at(1).get_raw_data()[get_bootloadersz()])->TlsCallbackNew = tls->get_callbacks_rva();
		}
		else
		{
			//If no callbacks exist, let's set address to null just in case
			tls->set_callbacks_rva(0);
		}

		//Clean up callback array, we don't need them anymore
		//We created them manually
		tls->clear_tls_callbacks();

		//Set new relative address
		//of data used to initialize thread local memory
		tls->set_raw_data_start_rva(pe_base::rva_from_section_offset(unpacker_added_section, data.size()));
		//Recalculate the address of these data end
		tls->recalc_raw_data_end_rva();

		//Rebuild TLS
		//Notify the rebuilder, that it is not needed to write data and callbacks
		//We do this manually (callbacks are already written to the right places)
		//Also we indicate that we don't need to strip null bytes at the end of the section
		rebuild_tls(image, *tls, unpacker_added_section, directory_pos, false, false, tls_data_expand_raw, true, false);

		//Add data used to initialize local thread memory to the section
		unpacker_added_section.get_raw_data() += tls->get_raw_data();
		//Now set "coderpub" section virtual size
		//taking into account SizeOfZeroFill of TLS field
		image.set_section_virtual_size(unpacker_added_section, data.size() + tls->get_size_of_zero_fill());
		//At last, strip unnecessary null bytes at the end of the section
		if (!image.has_reloc() && !image.has_exports() && !load_config.get())
			pe_utils::strip_nullbytes(unpacker_added_section.get_raw_data());
		//and recalculate its sizes (raw and virtual)
		image.prepare_section(unpacker_added_section);
	}

	if (image.has_reloc())
	{
		wsprintf(log_info, L"Building relocations.....");
		message->DoLogMessage(log_info, LogMessage::ERR_INFO);

		//Create relocation table list and a table
		relocation_table_list reloc_tables;

		{
			relocation_table table;
			//Set relocation table virtual address
			//It will be equal to the relative virtual address of the second added
			//section, because it stores the unpacker code with the variable to fix
			table.set_rva(unpacker_added_section.get_virtual_address());

			//Add relocation by original_image_base_offset offset from
			//parameters.h file of the unpacker
			table.add_relocation(relocation_entry(unpacker_added_section.get_virtual_address()+1, IMAGE_REL_BASED_HIGHLOW));

			//Add the table to the list
			reloc_tables.push_back(table);
		}

		//If a file has TLS
		if (tls.get())
		{
			wsprintf(log_info, L"Building TLS directory/callback relocations.....");
			message->DoLogMessage(log_info, LogMessage::ERR_INFO);
			//Calculate offset to TLS structure
			//relative to the beginning of second section
			DWORD tls_directory_offset = image.get_directory_rva(IMAGE_DIRECTORY_ENTRY_TLS)
				- image.section_from_directory(IMAGE_DIRECTORY_ENTRY_TLS).get_virtual_address();

			//Create new relocation table, as TLS table can be too far away
			//from original_image_base_offset. This can lead to relocation table addresses overflow
			relocation_table table;
			table.set_rva(image.get_directory_rva(IMAGE_DIRECTORY_ENTRY_TLS));
			//Add relocations for StartAddressOfRawData,
			//EndAddressOfRawData and AddressOfIndex fields
			//These fields are always not null
			table.add_relocation(relocation_entry(static_cast<WORD>(
				offsetof(IMAGE_TLS_DIRECTORY32, StartAddressOfRawData)), IMAGE_REL_BASED_HIGHLOW));
			table.add_relocation(relocation_entry(static_cast<WORD>(
				offsetof(IMAGE_TLS_DIRECTORY32, EndAddressOfRawData)), IMAGE_REL_BASED_HIGHLOW));
			table.add_relocation(relocation_entry(static_cast<WORD>(
				offsetof(IMAGE_TLS_DIRECTORY32, AddressOfIndex)), IMAGE_REL_BASED_HIGHLOW));

			//If TLS callbacks exist
			if (first_callback_offset)
			{
				//Add relocations for AddressOfCallBacks field
				//and for our empty callback address
				table.add_relocation(relocation_entry(static_cast<WORD>(offsetof(IMAGE_TLS_DIRECTORY32, AddressOfCallBacks)), IMAGE_REL_BASED_HIGHLOW));
				table.add_relocation(relocation_entry(static_cast<WORD>(tls->get_callbacks_rva() - table.get_rva()), IMAGE_REL_BASED_HIGHLOW));
			}

			reloc_tables.push_back(table);
		}

		//Rebuild relocations, placing them at the end
		//of section with the unpacker code
		rebuild_relocations(image, reloc_tables, unpacker_added_section, unpacker_added_section.get_raw_data().size(), true, !image.has_exports());
	}

	if (image.has_exports())
	{
		wsprintf(log_info, L"Rebuilding exports.....");
		message->DoLogMessage(log_info, LogMessage::ERR_INFO);
		rebuild_exports(image, exports_info, exports, unpacker_added_section, unpacker_added_section.get_raw_data().size(), true);
	}


	image.set_ep(image.rva_from_section_offset(unpacker_added_section, 0));
	image.remove_directory(IMAGE_DIRECTORY_ENTRY_IAT);
	image.strip_stub_overlay();

	std::string str = Mud_String::utf16toansi(filename);
	size_t lastindex = str.find_last_of(".");
	std::string outfile = str.substr(0, lastindex);
	outfile += "_mupakk" + str.substr(str.find_last_of("."));
	std::ofstream new_pe_file(outfile, std::ios::out | std::ios::binary | std::ios::trunc);
	if (!new_pe_file)
	{
		//If failed to create file - display an error message
		wsprintf(log_info, L"Failed to rebuild PE file!");
		message->DoLogMessage(log_info, LogMessage::ERR_ERROR);
		return -1;
	}
	rebuild_pe(image, new_pe_file, true, false);
	return 1;
}
