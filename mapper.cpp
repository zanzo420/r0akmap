/* This file is part of r0akmap by namazso, licensed under the MIT license:
*
* MIT License
*
* Copyright (c) namazso 2018
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/
#define NOIME
#define NOWINRES
#define NOGDICAPMASKS
#define NOVIRTUALKEYCODES
#define NOWINMESSAGES
#define NOWINSTYLES
#define NOSYSMETRICS
#define NOMENUS
#define NOICONS
#define NOKEYSTATES
#define NOSYSCOMMANDS
#define NORASTEROPS
#define NOSHOWWINDOW
#define OEMRESOURCE
#define NOATOM
#define NOCLIPBOARD
#define NOCOLOR
#define NOCTLMGR
#define NODRAWTEXT
#define NOGDI
#define NOUSER
#define NOMB
#define NOMEMMGR
#define NOMETAFILE
#define NOMINMAX
#define NOMSG
#define NOOPENFILE
#define NOSCROLL
#define NOSERVICE
#define NOSOUND
#define NOTEXTMETRIC
#define NOWH
#define NOWINOFFSETS
#define NOCOMM
#define NOKANJI
#define NOHELP
#define NOPROFILER
#define NODEFERWINDOWPOS
#define NOMCX
#define NOIME
#define NOPROXYSTUB
#define NOIMAGE
#define NO
#define NOTAPE
#define ANSI_ONLY

#include <windows.h>
#include <winternl.h>
#include <winnt.h>
#include <cstdint>
#include <cstddef>
#include <type_traits>
#include <memory>
#include <algorithm>

//#include "ntos.h"

namespace detail
{
	template <typename T, typename Enable = void>
	struct recursive_decay
	{
		using type = std::decay_t<T>;
	};

	template <typename T>
	struct recursive_decay<T, std::enable_if_t<std::is_pointer_v<T>>>
	{
		using type = std::add_pointer_t<typename recursive_decay<std::remove_pointer_t<T>>::type>;
	};

	template <typename T>
	using recursive_decay_t = typename recursive_decay<T>::type;
}

template <typename T = void, typename Ptr>
static auto offset_ptr(
	Ptr ptr,
	const std::ptrdiff_t offset
) -> std::conditional_t<std::is_same_v<T, void>, Ptr, T>
{
	auto address = (char*)(ptr)+offset;
	return (std::conditional_t<std::is_same_v<T, void>, Ptr, T>)(uintptr_t(address));
}

template <typename T, typename Old, typename New>
static auto rebase_ptr(T ptr, Old old_base, New new_base) -> detail::recursive_decay_t<T>
{
	return (detail::recursive_decay_t<T>)(
		(std::uintptr_t)(ptr)
		- (std::uintptr_t)(old_base)
		+ (std::uintptr_t)(new_base));
}

namespace detail
{
	// Implements FNV-1a hash algorithm
	template <size_t Size>
	class FnvHash
	{
	private:
		template <typename Type, Type OffsetBasis, Type Prime>
		struct SizeDependantData
		{
			using type = Type;
			constexpr static auto k_offset_basis = OffsetBasis;
			constexpr static auto k_prime = Prime;
		};

		template <size_t Bits>
		struct SizeSelector;

		template <>
		struct SizeSelector<32>
		{
			using type = SizeDependantData<std::uint32_t, 0x811c9dc5ul, 16777619ul>;
		};

		template <>
		struct SizeSelector<64>
		{
			using type = SizeDependantData<std::uint64_t, 0xcbf29ce484222325ull, 1099511628211ull>;
		};

		using data_t = typename SizeSelector<Size>::type;

	public:
		using hash = typename data_t::type;

	private:
		constexpr static auto k_offset_basis = data_t::k_offset_basis;
		constexpr static auto k_prime = data_t::k_prime;

	public:
		template <std::size_t N>
		static __forceinline constexpr auto hash_constexpr(const char(&str)[N], const std::size_t size = N) -> hash
		{
			return static_cast<hash>(1ull * (size == 1
				? (k_offset_basis ^ str[0])
				: (hash_constexpr(str, size - 1) ^ str[size - 1])) * k_prime);
		}

		static auto __forceinline hash_runtime(const char* str) -> hash
		{
			auto result = k_offset_basis;
			do
			{
				result ^= *str++;
				result *= k_prime;
			} while (*(str - 1) != '\0');

			return result;
		}
	};

	template <typename T, T V>
	struct ForceCX
	{
		constexpr static T value = V;
	};
}

using fnv = ::detail::FnvHash<sizeof(void*) * 8>;

#define FNV(str) (::detail::ForceCX<fnv::hash, fnv::hash_constexpr(str)>::value)


namespace platform
{
	static __forceinline auto get_nt_headers(void* module) -> const IMAGE_NT_HEADERS*
	{
		const auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
		const auto nt_header = reinterpret_cast<const IMAGE_NT_HEADERS*>(offset_ptr(module, dos_header->e_lfanew));

		return nt_header;
	}

	template <typename T>
	static __forceinline auto get_data_directory(void* module, const IMAGE_NT_HEADERS* nt_headers,
		const uint32_t dir) -> T*
	{
		const auto offset = nt_headers->OptionalHeader.DataDirectory[dir].VirtualAddress;

		return offset ? reinterpret_cast<T*>(offset_ptr(module, offset)) : nullptr;
	}

	template <typename T>
	static __forceinline auto get_data_directory(void* module, const uint32_t dir) -> T*
	{
		return get_data_directory<T>(module, get_nt_headers(module), dir);
	}

	static auto __forceinline get_export_by_name(void* module, const fnv::hash function_hash) -> void*
	{
		const auto module_addr = std::uintptr_t(module);
		const auto export_dir = get_data_directory<IMAGE_EXPORT_DIRECTORY>(module, IMAGE_DIRECTORY_ENTRY_EXPORT);

		if (!export_dir)
			return nullptr;

		const auto names = reinterpret_cast<uint32_t*>(module_addr + export_dir->AddressOfNames);
		const auto funcs = reinterpret_cast<uint32_t*>(module_addr + export_dir->AddressOfFunctions);
		const auto ords = reinterpret_cast<uint16_t*>(module_addr + export_dir->AddressOfNameOrdinals);

		if (names && funcs && ords)
		{
			const auto num = std::min(export_dir->NumberOfNames, export_dir->AddressOfFunctions);
			for (auto i = 0u; i < num; i++)
			{
				const auto export_name = reinterpret_cast<const char*>(module_addr + names[i]);
				if (fnv::hash_runtime(export_name) == function_hash)
				{
					return offset_ptr(module, funcs[ords[i]]);
				}
			}
		}

		return nullptr;
	}

	static auto __forceinline get_export_by_ordinal(void* module, const std::uint16_t ordinal) -> void*
	{
		const auto module_addr = std::uintptr_t(module);
		const auto export_dir = get_data_directory<IMAGE_EXPORT_DIRECTORY>(module, IMAGE_DIRECTORY_ENTRY_EXPORT);

		if (!export_dir)
			return nullptr;

		const auto funcs = reinterpret_cast<uint32_t*>(module_addr + export_dir->AddressOfFunctions);

		return offset_ptr(module, funcs[ordinal]);
	}

	static auto __forceinline get_module_size(void* module) -> std::size_t
	{
		return get_nt_headers(module)->OptionalHeader.SizeOfImage;
	}
}

#define PAGE_SIZE 0x1000

typedef enum _POOL_TYPE
{
	NonPagedPool = 0,
	NonPagedPoolExecute = 0,
	PagedPool = 1,
	NonPagedPoolMustSucceed = 2,
	DontUseThisType = 3,
	NonPagedPoolCacheAligned = 4,
	PagedPoolCacheAligned = 5,
	NonPagedPoolCacheAlignedMustS = 6,
	MaxPoolType = 7,
	NonPagedPoolBase = 0,
	NonPagedPoolBaseMustSucceed = 2,
	NonPagedPoolBaseCacheAligned = 4,
	NonPagedPoolBaseCacheAlignedMustS = 6,
	NonPagedPoolSession = 32,
	PagedPoolSession = 33,
	NonPagedPoolMustSucceedSession = 34,
	DontUseThisTypeSession = 35,
	NonPagedPoolCacheAlignedSession = 36,
	PagedPoolCacheAlignedSession = 37,
	NonPagedPoolCacheAlignedMustSSession = 38,
	NonPagedPoolNx = 512,
	NonPagedPoolNxCacheAligned = 516,
	NonPagedPoolSessionNx = 544
} POOL_TYPE;

using PfnExAllocatePool = PVOID(NTAPI *)(
	_In_ POOL_TYPE PoolType,
	_In_ SIZE_T NumberOfBytes);

__forceinline void sh_memcpy(void* dst, const void* src, std::size_t size)
{
	for (auto i = 0u; i < size; ++i)
		reinterpret_cast<uint8_t*>(dst)[i] =
		reinterpret_cast<const uint8_t*>(src)[i];
}


[[gnu::flatten]]
void map_driver(void* ntoskrnl, void* driver)
{
	auto image = driver;
	const auto nt_headers = platform::get_nt_headers(image);
	const auto optional_header = &nt_headers->OptionalHeader;

	// Allocate memory and map ourselved in there
	{
		auto ExAllocatePool = PfnExAllocatePool(platform::get_export_by_name(ntoskrnl, FNV("ExAllocatePool")));

		// Make sure to put our image on a page boundary
		auto alloc_addr = std::uintptr_t(ExAllocatePool(NonPagedPoolExecute, optional_header->SizeOfImage + PAGE_SIZE));

		alloc_addr += PAGE_SIZE;

		alloc_addr &= ~(PAGE_SIZE - 1);

		const auto exbuffer = reinterpret_cast<void*>(alloc_addr);

		const auto image_section_header = PIMAGE_SECTION_HEADER(nt_headers + 1);

		// Copy the sections to the buffer
		for (auto i = 0u; i < nt_headers->FileHeader.NumberOfSections; i++)
			sh_memcpy(
				offset_ptr(exbuffer, image_section_header[i].VirtualAddress),
				offset_ptr(image, image_section_header[i].PointerToRawData),
				image_section_header[i].SizeOfRawData);

		image = exbuffer;
	}

	//const auto optional_header = &platform::get_nt_headers(image)->OptionalHeader;

	const auto delta = std::uintptr_t(image) - optional_header->ImageBase;

	// Relocate the image
	for (auto entry = platform::get_data_directory<IMAGE_BASE_RELOCATION>(image, nt_headers, IMAGE_DIRECTORY_ENTRY_BASERELOC);
		entry && entry->VirtualAddress;
		entry = offset_ptr(entry, entry->SizeOfBlock))
		if (entry->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			const auto count = (entry->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(std::uint16_t);
			const auto list = reinterpret_cast<const std::uint16_t*>(entry + 1);

			for (auto i = 0u; i < count; i++)
			{
				const auto list_entry = list[i];
				if (list_entry)
				{
					const auto reloc_address = offset_ptr(image, (entry->VirtualAddress + (list_entry & 0x0FFF)));
					switch (list_entry >> 12)
					{
					case IMAGE_REL_BASED_HIGHLOW:
						*reinterpret_cast<std::uint32_t*>(reloc_address) += static_cast<std::uint32_t>(delta);
						break;
					case IMAGE_REL_BASED_DIR64:
						*reinterpret_cast<std::uint64_t*>(reloc_address) += delta;
						break;
					default:
						break;
					}
				}
			}
		}


	// Resolve imports
	for (auto entry = platform::get_data_directory<IMAGE_IMPORT_DESCRIPTOR>(image, nt_headers, IMAGE_DIRECTORY_ENTRY_IMPORT);
		entry && entry->Characteristics;
		entry++)
	{
		const auto imported_module = ntoskrnl;

		for (auto orig_first_thunk = offset_ptr<IMAGE_THUNK_DATA*>(image, entry->OriginalFirstThunk),
			first_thunk = offset_ptr<IMAGE_THUNK_DATA*>(image, entry->FirstThunk);
			orig_first_thunk->u1.AddressOfData;
			orig_first_thunk++, first_thunk++)
		{
			std::uintptr_t import;

			if (orig_first_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// Import by ordinal
				const auto ordinal = std::uint16_t(orig_first_thunk->u1.Ordinal & 0xFFFF);
				import = std::uintptr_t(platform::get_export_by_ordinal(imported_module, ordinal));
			}
			else
			{
				// Import by name
				const auto import_by_name = offset_ptr<IMAGE_IMPORT_BY_NAME*>(image, orig_first_thunk->u1.AddressOfData);
				import = std::uintptr_t(platform::get_export_by_name(imported_module, fnv::hash_runtime(import_by_name->Name)));
			}

			first_thunk->u1.Function = import;
		}
	}

	using driver_entry_t = uintptr_t(*)(void*, void*, void*, void*);
	const auto entry_point = reinterpret_cast<driver_entry_t>(offset_ptr(image, optional_header->AddressOfEntryPoint));
	if (entry_point)
		entry_point(nullptr, nullptr, nullptr, ntoskrnl);
}
