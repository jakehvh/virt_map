#pragma once

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <string>
#include <vector>

namespace virt_map
{
	using load_library_t = HINSTANCE( * )( const char* );
	using get_proc_addr_t = FARPROC( * )( HMODULE, LPCSTR );
	using rtl_add_function_table_t = BOOL( * )( PRUNTIME_FUNCTION, DWORD, DWORD64 );
	using rtl_insert_inverted_function_table_t = void* ( * )( DWORD64, SIZE_T );
	using ldrp_handle_tls_data_t = NTSTATUS( * )( PLDR_DATA_TABLE_ENTRY );

	struct f_shellcode_data
	{
		void* module_base;
		void* reserved_data;
		bool shell_done;
		load_library_t load_library_fn;
		get_proc_addr_t get_proc_addr_fn;
		rtl_add_function_table_t rtl_add_function_table_fn;
		rtl_insert_inverted_function_table_t rtl_insert_inverted_function_table_fn;
		ldrp_handle_tls_data_t ldrp_handle_tls_data_fn;
	};

	struct f_reserved_data
	{
		uint64_t module_base;
		uint64_t module_size;
	};

	void __stdcall shell_func( f_shellcode_data* shell_data );

	class target_process
	{
	public:
		target_process( std::wstring proc_name ) : m_pid( get_pid( proc_name ) ), m_tid( get_tid_highest_cycle( m_pid ) ) { }

	public:
		uint32_t map_module( uint8_t* data, size_t size );

	private:
		template <typename t>
		t read( uint64_t addr ) const
		{
			t out{ };

			if ( !ReadProcessMemory( m_proc_handle, reinterpret_cast< void* >( addr ), &out, sizeof( t ), nullptr ) )
				return out;

			return out;
		}

		bool read( uint64_t addr, void* out, size_t size ) const
		{
			if ( !ReadProcessMemory( m_proc_handle, reinterpret_cast< void* >( addr ), &out, size, nullptr ) )
				return false;

			return true;
		}

		template <typename t>
		bool write( uint64_t addr, t value ) const
		{
			if ( !WriteProcessMemory( m_proc_handle, reinterpret_cast< void* >( addr ), &value, sizeof( t ), nullptr ) )
				return false;

			return true;
		}

		bool write( uint64_t addr, void* value, size_t size ) const
		{
			if ( !WriteProcessMemory( m_proc_handle, reinterpret_cast< void* >( addr ), value, size, nullptr ) )
				return false;

			return true;
		}

		uint64_t allocate( size_t size, uint32_t protect ) const
		{
			return reinterpret_cast< uint64_t >( VirtualAllocEx( m_proc_handle, nullptr, size, MEM_COMMIT | MEM_RESERVE, protect ) );
		}

		bool free( uint64_t addr ) const
		{
			return VirtualFreeEx( m_proc_handle, reinterpret_cast< void* >( addr ), 0, MEM_RELEASE );
		}

		MODULEENTRY32W get_remote_module_entry( std::wstring module_name );
		uint64_t find_pattern( std::wstring module_name, const char* pattern, const char* mask );

		uint32_t get_pid( std::wstring proc_name ) const;
		uint32_t get_tid_highest_cycle( uint32_t pid ) const;

		void swap_rip( uint64_t rip );
		void restore_rip( );

	private:
		uint32_t m_pid = 0;
		uint32_t m_tid = 0;
		HANDLE m_proc_handle = nullptr;
		HANDLE m_thread_handle = nullptr;
		CONTEXT m_thread_ctx;
		uint64_t m_orig_rip = 0;
	};
}
