#include "virt_map.hpp"

MODULEENTRY32W virt_map::target_process::get_remote_module_entry( std::wstring module_name )
{
	MODULEENTRY32W module_entry { sizeof( MODULEENTRY32W ) };

	auto snap_shot_handle = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_pid );
	if ( snap_shot_handle == INVALID_HANDLE_VALUE )
		return module_entry;

	if ( !Module32FirstW( snap_shot_handle, &module_entry ) )
	{
		CloseHandle( snap_shot_handle );
		return module_entry;
	}

	do
	{
		if ( module_entry.szModule == module_name )
		{
			CloseHandle( snap_shot_handle );
			return module_entry;
		}
	}
	while ( Module32NextW( snap_shot_handle, &module_entry ) );

	CloseHandle( snap_shot_handle );
	return module_entry;
}

uint64_t virt_map::target_process::find_pattern( std::wstring module_name, const char* pattern, const char* mask )
{
	auto module_entry = get_remote_module_entry( module_name );
	if ( !module_entry.modBaseAddr )
		return 0;

	auto image_start = reinterpret_cast< uint64_t >( module_entry.modBaseAddr );
	auto image_end = image_start + module_entry.modBaseSize;

	std::vector<uint8_t> buffer( image_end - image_start );
	ReadProcessMemory( m_proc_handle, reinterpret_cast< void* >( image_start ), buffer.data( ), buffer.size( ), nullptr );

	size_t pattern_len = strlen( mask );
	for ( size_t i = 0; i <= buffer.size( ) - pattern_len; ++i )
	{
		bool found = true;

		for ( size_t j = 0; j < pattern_len; ++j )
		{
			if ( mask[ j ] != '?' && pattern[ j ] != static_cast< char >( buffer[ i + j ] ) )
			{
				found = false;
				break;
			}
		}

		if ( found )
			return image_start + i;
	}

	return 0;
}

uint32_t virt_map::target_process::get_pid( std::wstring proc_name ) const
{
	PROCESSENTRY32W proc_entry { sizeof( PROCESSENTRY32W ) };

	auto snap_shot_handle = CreateToolhelp32Snapshot( TH32CS_SNAPALL, 0 );
	if ( snap_shot_handle == INVALID_HANDLE_VALUE )
		return 0;

	if ( !Process32FirstW( snap_shot_handle, &proc_entry ) )
	{
		CloseHandle( snap_shot_handle );
		return 0;
	}

	do
	{
		if ( proc_entry.szExeFile == proc_name )
		{
			CloseHandle( snap_shot_handle );
			return proc_entry.th32ProcessID;
		}
	}
	while ( Process32NextW( snap_shot_handle, &proc_entry ) );

	CloseHandle( snap_shot_handle );
	return 0;
}

uint32_t virt_map::target_process::get_tid_highest_cycle( uint32_t pid ) const
{
	THREADENTRY32 thread_entry { sizeof( THREADENTRY32 ) };
	THREADENTRY32 best_thread_entry { };
	uint64_t best_cycle_time = 0;

	auto snap_shot_handle = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
	if ( snap_shot_handle == INVALID_HANDLE_VALUE )
		return 0;

	if ( !Thread32First( snap_shot_handle, &thread_entry ) )
	{
		CloseHandle( snap_shot_handle );
		return 0;
	}

	do
	{
		if ( thread_entry.th32OwnerProcessID != pid )
			continue;

		auto thread_handle = OpenThread( THREAD_QUERY_INFORMATION, FALSE, thread_entry.th32ThreadID );
		if ( thread_handle == INVALID_HANDLE_VALUE )
			continue;

		uint64_t cycle_time = 0;
		if ( QueryThreadCycleTime( thread_handle, &cycle_time ) )
		{
			if ( cycle_time > best_cycle_time )
			{
				best_cycle_time = cycle_time;
				best_thread_entry = thread_entry;
			}
		}

		CloseHandle( thread_handle );
	}
	while ( Thread32Next( snap_shot_handle, &thread_entry ) );

	CloseHandle( snap_shot_handle );
	return best_thread_entry.th32ThreadID;
}

void virt_map::target_process::swap_rip( uint64_t rip )
{
	m_thread_ctx.ContextFlags = CONTEXT_FULL;
	if ( !GetThreadContext( m_thread_handle, &m_thread_ctx ) )
		return;

	m_orig_rip = m_thread_ctx.Rip;

	SuspendThread( m_thread_handle );

	m_thread_ctx.Rip = rip;
	SetThreadContext( m_thread_handle, &m_thread_ctx );

	ResumeThread( m_thread_handle );
}

void virt_map::target_process::restore_rip( )
{
	SuspendThread( m_thread_handle );

	m_thread_ctx.Rip = m_orig_rip;
	SetThreadContext( m_thread_handle, &m_thread_ctx );

	ResumeThread( m_thread_handle );
}

uint32_t virt_map::target_process::map_module( uint8_t* data, size_t size )
{
	auto dos_header = reinterpret_cast< IMAGE_DOS_HEADER* >( data );
	if ( dos_header->e_magic != IMAGE_DOS_SIGNATURE )
		return 0x1001;

	auto nt_headers = reinterpret_cast< IMAGE_NT_HEADERS* >( reinterpret_cast< BYTE* >( data ) + dos_header->e_lfanew );
	if ( nt_headers->Signature != IMAGE_NT_SIGNATURE )
		return 0x1002;

	m_proc_handle = OpenProcess( PROCESS_ALL_ACCESS, FALSE, m_pid );
	if ( m_proc_handle == INVALID_HANDLE_VALUE )
		return 0x1003;

	m_thread_handle = OpenThread( THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, m_tid );
	if ( m_thread_handle == INVALID_HANDLE_VALUE )
		return 0x1004;

	auto module_base = allocate( nt_headers->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE );
	if ( !module_base )
		return 0x1005;

	if ( !write( module_base, data, 0x1000 ) )
	{
		free( module_base );
		return 0x1006;
	}

	auto current_section = IMAGE_FIRST_SECTION( nt_headers );
	for ( int s = 0; s != nt_headers->FileHeader.NumberOfSections; s++, current_section++ )
	{
		if ( !current_section->SizeOfRawData )
			continue;

		if ( !write( module_base + current_section->VirtualAddress, data + current_section->PointerToRawData, current_section->SizeOfRawData ) )
		{
			free( module_base );
			return 0x1007;
		}
	}

	f_reserved_data reserved_data{ };
	reserved_data.module_base = module_base;
	reserved_data.module_size = nt_headers->OptionalHeader.SizeOfImage;

	auto reserved_data_addr = allocate( sizeof( f_reserved_data ), PAGE_READWRITE );
	if ( !reserved_data_addr )
	{
		free( module_base );
		return 0x1008;
	}

	if ( !write( reserved_data_addr, &reserved_data, sizeof( f_reserved_data ) ) )
	{
		free( module_base );
		free( reserved_data_addr );
		return 0x1009;
	}

	f_shellcode_data shell_data{ };
	shell_data.module_base = reinterpret_cast< void* >( module_base );
	shell_data.reserved_data = reinterpret_cast< void* >( reserved_data_addr );
	shell_data.shell_done = false;
	shell_data.load_library_fn = reinterpret_cast< load_library_t >( LoadLibraryA );
	shell_data.get_proc_addr_fn = reinterpret_cast< get_proc_addr_t >( GetProcAddress );
	shell_data.rtl_add_function_table_fn = reinterpret_cast< rtl_add_function_table_t >( RtlAddFunctionTable );
	shell_data.rtl_insert_inverted_function_table_fn = reinterpret_cast< rtl_insert_inverted_function_table_t >( find_pattern( L"ntdll.dll", "\x48\x89\x5C\x24\x00\x57\x48\x83\xEC\x00\x8B\xDA\x4C\x8D\x44\x24", "xxxx?xxxx?xxxxx" ) );
	shell_data.ldrp_handle_tls_data_fn = reinterpret_cast< ldrp_handle_tls_data_t >( find_pattern( L"ntdll.dll", "\x48\x89\x5C\x24\x00\x48\x89\x74\x24\x00\x48\x89\x7C\x24\x00\x41\x54\x41\x56\x41\x57\x48\x81\xEC\x00\x00\x00\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x33\xC4\x48\x89\x84\x24\x00\x00\x00\x00\x48\x8B\xC1", "xxxx?xxxx?xxxx?xxxxxxxxx????xxx????xxxxxxx????xxx" ) );

	if( !shell_data.rtl_insert_inverted_function_table_fn || !shell_data.ldrp_handle_tls_data_fn )
	{
		free( module_base );
		free( reserved_data_addr );
		return 0x1011;
	}

	auto shell_data_addr = allocate( sizeof( f_shellcode_data ), PAGE_READWRITE );
	if ( !shell_data_addr )
	{
		free( module_base );
		free( reserved_data_addr );
		return 0x1012;
	}

	if ( !write( shell_data_addr, &shell_data, sizeof( f_shellcode_data ) ) )
	{
		free( module_base );
		free( reserved_data_addr );
		free( shell_data_addr );
		return 0x1013;
	}

	auto shellcode_addr = allocate( 0x1000, PAGE_EXECUTE_READWRITE );
	if ( !shellcode_addr )
	{
		free( module_base );
		free( reserved_data_addr );
		free( shell_data_addr );
		return 0x1014;
	}

	if ( !write( shellcode_addr, shell_func, 0x1000 ) )
	{
		free( module_base );
		free( reserved_data_addr );
		free( shell_data_addr );
		free( shellcode_addr );
		return 0x1015;
	}

	uint8_t thread_shell[ ] =
	{
		0x55,
		0x48, 0x89, 0xe5,
		0x48, 0x83, 0xe4, 0xf0,
		0x48, 0x83, 0xec, 0x20,
		0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xd0,
		0x48, 0x83, 0xc4, 0x20,
		0x48, 0x89, 0xec,
		0x5d,
		0xc3
	};

	*reinterpret_cast< uint64_t* > ( &thread_shell[ 14 ] ) = shell_data_addr;
	*reinterpret_cast< uint64_t* > ( &thread_shell[ 24 ] ) = shellcode_addr;

	auto thread_shell_addr = allocate( sizeof( thread_shell ), PAGE_EXECUTE_READWRITE );
	if ( !thread_shell_addr )
	{
		free( module_base );
		free( reserved_data_addr );
		free( shell_data_addr );
		free( shellcode_addr );
		return 0x1016;
	}

	if ( !write( thread_shell_addr, thread_shell, sizeof( thread_shell ) ) )
	{
		free( module_base );
		free( reserved_data_addr );
		free( shell_data_addr );
		free( shellcode_addr );
		free( thread_shell_addr );
		return 0x1017;
	}

	swap_rip( thread_shell_addr );

	bool thread_return = false;
	while ( !thread_return )
	{
		auto shell_data = read<f_shellcode_data>( shell_data_addr );
		thread_return = shell_data.shell_done;

		Sleep( 50 );
	}

	restore_rip( );

	auto current_section2 = IMAGE_FIRST_SECTION( nt_headers );
	for ( int s = 0; s != nt_headers->FileHeader.NumberOfSections; s++, current_section2++ )
	{
		auto current_section_name = reinterpret_cast< char* >( current_section2->Name );
		if ( !strcmp( current_section_name, ".rsrc" ) || !strcmp( current_section_name, ".reloc" ) )
		{
			auto empty_buffer = new uint8_t[ current_section2->Misc.VirtualSize ];
			memset( empty_buffer, 0, current_section2->Misc.VirtualSize );

			write( module_base + current_section2->VirtualAddress, empty_buffer, current_section2->Misc.VirtualSize );

			delete[ ] empty_buffer;
		}
	}

	free( shell_data_addr );
	free( shellcode_addr );
	free( thread_shell_addr );

	CloseHandle( m_thread_handle );
	CloseHandle( m_proc_handle );

	return 0;
}

#pragma runtime_checks( "", off )
#pragma optimize( "", off )

void __stdcall virt_map::shell_func( f_shellcode_data* shell_data )
{
	auto dos_header = reinterpret_cast< IMAGE_DOS_HEADER* >( shell_data->module_base );
	auto nt_headers = reinterpret_cast< IMAGE_NT_HEADERS* >( reinterpret_cast< uint8_t* >( shell_data->module_base ) + dos_header->e_lfanew );
	auto entry_point = reinterpret_cast< int32_t( * )( void*, uint32_t, void* ) >( reinterpret_cast< uint64_t >( shell_data->module_base ) + nt_headers->OptionalHeader.AddressOfEntryPoint );

	auto relocation_directory = nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];
	auto import_directory = nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
	auto exception_directory = nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXCEPTION ];
	auto tls_directory = nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_TLS ];

	auto relocation_delta = reinterpret_cast< uint64_t >( shell_data->module_base ) - nt_headers->OptionalHeader.ImageBase;
	if ( relocation_directory.Size )
	{
		auto relocation_start = reinterpret_cast< IMAGE_BASE_RELOCATION* >( reinterpret_cast< uint64_t >( shell_data->module_base ) + relocation_directory.VirtualAddress );
		auto relocation_end = reinterpret_cast< IMAGE_BASE_RELOCATION* >( reinterpret_cast< uint64_t >( relocation_start ) + relocation_directory.Size );

		while ( relocation_start < relocation_end && relocation_start->SizeOfBlock )
		{
			auto relocation_count = ( relocation_start->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( uint16_t );
			auto relocation_info = reinterpret_cast< uint16_t* >( relocation_start + 1 );

			for ( int i = 0; i < relocation_count; ++i )
			{
				auto type = relocation_info[ i ] >> 12;
				auto offset = relocation_info[ i ] & 0x0FFF;

				if ( type == IMAGE_REL_BASED_DIR64 )
				{
					auto patch_address = reinterpret_cast< uint64_t* >( reinterpret_cast< uint64_t >( shell_data->module_base ) + relocation_start->VirtualAddress + offset );
					*patch_address += relocation_delta;
				}
			}
			relocation_start = reinterpret_cast< IMAGE_BASE_RELOCATION* >( reinterpret_cast< uint64_t >( relocation_start ) + relocation_start->SizeOfBlock );
		}
	}

	if ( import_directory.Size )
	{
		auto import_descriptor = reinterpret_cast< IMAGE_IMPORT_DESCRIPTOR* >( reinterpret_cast< uint64_t >( shell_data->module_base ) + import_directory.VirtualAddress );
		while ( import_descriptor->Name )
		{
			auto module_name = reinterpret_cast< char* >( reinterpret_cast< uint64_t >( shell_data->module_base ) + import_descriptor->Name );
			auto module_handle = shell_data->load_library_fn( module_name );
			if ( !module_handle )
			{
				++import_descriptor;
				continue;
			}

			auto orig_first_thunk = reinterpret_cast< IMAGE_THUNK_DATA* >( reinterpret_cast< uint64_t >( shell_data->module_base ) + import_descriptor->OriginalFirstThunk );
			auto first_thunk = reinterpret_cast< IMAGE_THUNK_DATA* >( reinterpret_cast< uint64_t >( shell_data->module_base ) + import_descriptor->FirstThunk );

			while ( orig_first_thunk->u1.AddressOfData )
			{
				FARPROC func_addr = nullptr;

				if ( orig_first_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG )
				{
					auto ordinal = static_cast< uint8_t >( orig_first_thunk->u1.Ordinal & 0xFFFF );
					func_addr = shell_data->get_proc_addr_fn( module_handle, reinterpret_cast< const char* >( ordinal ) );
				}
				else
				{
					auto import_by_name = reinterpret_cast< IMAGE_IMPORT_BY_NAME* >( reinterpret_cast< uint64_t >( shell_data->module_base ) + first_thunk->u1.AddressOfData );
					func_addr = shell_data->get_proc_addr_fn( module_handle, import_by_name->Name );
				}

				if ( func_addr )
					first_thunk->u1.Function = reinterpret_cast< uint64_t >( func_addr );

				++orig_first_thunk;
				++first_thunk;
			}

			++import_descriptor;
		}
	}

	if ( exception_directory.Size )
	{
		auto entries = reinterpret_cast< IMAGE_RUNTIME_FUNCTION_ENTRY* >( reinterpret_cast< uint64_t >( shell_data->module_base ) + exception_directory.VirtualAddress );
		auto entry_count = exception_directory.Size / sizeof( IMAGE_RUNTIME_FUNCTION_ENTRY );

		shell_data->rtl_add_function_table_fn( entries, entry_count, reinterpret_cast< uint64_t >( shell_data->module_base ) );
		shell_data->rtl_insert_inverted_function_table_fn( reinterpret_cast< uint64_t >( shell_data->module_base ), nt_headers->OptionalHeader.SizeOfImage );
	}

	if ( tls_directory.Size )
	{
		auto my_ldr_entry = new LDR_DATA_TABLE_ENTRY;
		__stosb( reinterpret_cast< uint8_t* >( my_ldr_entry ), 0, sizeof( LDR_DATA_TABLE_ENTRY ) ); //glorified memset

		my_ldr_entry->DllBase = shell_data->module_base;

		shell_data->ldrp_handle_tls_data_fn( my_ldr_entry );
		delete my_ldr_entry;

		auto tls_start = reinterpret_cast< IMAGE_TLS_DIRECTORY* >( reinterpret_cast< uint64_t >( shell_data->module_base ) + tls_directory.VirtualAddress );
		auto tls_callback = reinterpret_cast< PIMAGE_TLS_CALLBACK* >( tls_start->AddressOfCallBacks );

		while ( *tls_callback )
		{
			auto callback_func = *tls_callback;
			callback_func( shell_data->module_base, DLL_PROCESS_ATTACH, nullptr );

			++tls_callback;
		}
	}

	entry_point( shell_data->module_base, DLL_PROCESS_ATTACH, shell_data->reserved_data );
	shell_data->shell_done = true;
}