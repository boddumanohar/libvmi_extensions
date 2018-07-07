// // Bareflank Extended APIs
// Copyright (C) 2018 Assured Information Security, Inc.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <bfvmm/vcpu/vcpu_factory.h>
#include <bfvmm/hve/arch/intel_x64/vcpu/vcpu.h>
#include <bfvmm/hve/arch/intel_x64/exit_handler/exit_handler.h>
#include <bfdebug.h>
#include <bfvmm/memory_manager/buddy_allocator.h>
#include <bfvmm/memory_manager/arch/x64/unique_map.h>
#include "json.hpp"
#include <stdlib.h>
#include <string.h>
#include <eapis/hve/arch/intel_x64/hve.h>
#include <eapis/hve/arch/intel_x64/vic.h>
#include <eapis/hve/arch/intel_x64/ept.h>
#include <eapis/vcpu/arch/intel_x64/vcpu.h>

using nlohmann::json;
using namespace eapis::intel_x64;
using namespace eapis::intel_x64::ept;

namespace ept = eapis::intel_x64::ept;
namespace vmcs = ::intel_x64::vmcs;

const uint64_t page_size_bytes = 0x200000ULL;
const uint64_t page_count = 0x8000ULL;

namespace libvmi
{


class vcpu : public eapis::intel_x64::vcpu
{
private:

std::unique_ptr<ept::memory_map> m_mem_map;
bool m_have_trapped_write_violation = false;

void enable_ept()
    {
        m_mem_map = std::make_unique<ept::memory_map>();

	uint64_t addr;
        for (auto i = 0ULL; i < page_count; i++) {
            addr = i * page_size_bytes;
            ept::identity_map_2m(*m_mem_map, addr);
            auto &entry = m_mem_map->gpa_to_epte(addr); //leaf

            ept::epte::read_access::enable(entry);
            ept::epte::write_access::enable(entry);
            ept::epte::execute_access::disable(entry);
        }

        auto eptp = ept::eptp(*m_mem_map);
        vmcs::ept_pointer::set(eptp);
        vmcs::secondary_processor_based_vm_execution_controls::enable_ept::enable();
    }

void register_ept_handlers()
    {
        auto hve = this->hve();

        hve->add_ept_read_violation_handler(
            eapis::intel_x64::ept_violation::handler_delegate_t::create<vcpu, &vcpu::handle_read_violation>(this)
        );

        hve->add_ept_write_violation_handler(
            eapis::intel_x64::ept_violation::handler_delegate_t::create<vcpu, &vcpu::handle_write_violation>(this)
        );

        hve->add_ept_execute_violation_handler(
            eapis::intel_x64::ept_violation::handler_delegate_t::create<vcpu, &vcpu::handle_execute_violation>(this)
        );

        hve->add_ept_misconfiguration_handler(
            eapis::intel_x64::ept_misconfiguration::handler_delegate_t::create<vcpu, &vcpu::handle_ept_misconfiguration>(this)
        );

        hve->ept_misconfiguration()->enable_log();
        hve->ept_violation()->enable_log();
    }

    bool handle_ept_misconfiguration(
        gsl::not_null<vmcs_t *> vmcs,
        eapis::intel_x64::ept_misconfiguration::info_t &info)
    {
        bfignored(vmcs);
        bfignored(info);

        info.ignore_advance = true;
        vmcs::secondary_processor_based_vm_execution_controls::enable_ept::disable();

        for (auto i = 0ULL; i < page_count; i++) {
            auto addr = i * page_size_bytes;
            auto &entry = m_mem_map->gpa_to_epte(addr);

            ept::epte::read_access::enable(entry);
            ept::epte::write_access::enable(entry);
            ept::epte::execute_access::disable(entry);
        }

        vmcs::secondary_processor_based_vm_execution_controls::enable_ept::enable();

        return true;
    }

    bool handle_read_violation(
        gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs,
        eapis::intel_x64::ept_violation::info_t &info)
    {
        bfignored(vmcs);
        bfignored(info);

        info.ignore_advance = true;
        vmcs::secondary_processor_based_vm_execution_controls::enable_ept::disable();

        return true;
    }

    bool handle_write_violation(
        gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs,
        eapis::intel_x64::ept_violation::info_t &info)
    {
        bfignored(vmcs);
        bfignored(info);

        if (m_have_trapped_write_violation) {
            return true;
        }

        m_have_trapped_write_violation = true;
        info.ignore_advance = true;
        vmcs::secondary_processor_based_vm_execution_controls::enable_ept::disable();

        for (auto i = 0ULL; i < page_count; i++) {
            auto addr = i * page_size_bytes;
            auto &entry = m_mem_map->gpa_to_epte(addr);

            ept::epte::read_access::disable(entry);
            ept::epte::write_access::disable(entry);
            ept::epte::execute_access::enable(entry);
        }

        vmcs::secondary_processor_based_vm_execution_controls::enable_ept::enable();

        return true;
    }

    bool handle_execute_violation(
        gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs,
        eapis::intel_x64::ept_violation::info_t &info)
    {
        bfignored(vmcs);
        bfignored(info);

        info.ignore_advance = true;
        vmcs::secondary_processor_based_vm_execution_controls::enable_ept::disable();

        for (auto i = 0ULL; i < page_count; i++) {
            auto addr = i * page_size_bytes;
            auto &entry = m_mem_map->gpa_to_epte(addr);

            ept::epte::read_access::enable(entry);
            ept::epte::write_access::disable(entry);
            ept::epte::execute_access::enable(entry);
        }

        vmcs::secondary_processor_based_vm_execution_controls::enable_ept::enable();

        return true;
    }

public:

    using handler_t = bool(gsl::not_null<bfvmm::intel_x64::vmcs *>);
    using handler_delegate_t = delegate<handler_t>;

    vcpu(vcpuid::type id) : eapis::intel_x64::vcpu{id}
    {
	this->register_ept_handlers();
	this->enable_ept();

        exit_handler()->add_handler(
            intel_x64::vmcs::exit_reason::basic_exit_reason::vmcall,
            handler_delegate_t::create<vcpu, &vcpu::_vmcall_handler>(this)
        );
    }

    bool _vmcall_handler(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs) {

        uint64_t id = vmcs->save_state()->rax;

        if (id == 1) {

            bfdebug_info(0, "vmcall handled");
        }
        else if(id == 2) {
            get_register_data(vmcs);
        }
        else if (id == 3) {
            set_register(vmcs);
        }
        else if (id == 4) {
            get_memmap(vmcs);
        }
        else if (id == 5) {
            get_memmap_ept(vmcs);
        }
	else if (id == 6) {
            get_paddr(vmcs);
        }
        else if (id == 7) {
            test_ept(vmcs);
        }
	return advance(vmcs);
    }

    void get_register_data(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs) {
        json j;
        j["RAX"] = vmcs->save_state()->rax;
        j["RBX"] = vmcs->save_state()->rbx;
        j["RCX"] = vmcs->save_state()->rcx;
        j["RDX"] = vmcs->save_state()->rdx;
        j["R08"] = vmcs->save_state()->r08;
        j["R09"] = vmcs->save_state()->r09;
        j["R10"] = vmcs->save_state()->r10;
        j["R11"] = vmcs->save_state()->r11;
        j["R12"] = vmcs->save_state()->r12;
        j["R13"] = vmcs->save_state()->r13;
        j["R14"] = vmcs->save_state()->r14;
        j["R15"] = vmcs->save_state()->r15;
        j["RBP"] = vmcs->save_state()->rbp;
        j["RSI"] = vmcs->save_state()->rsi;
        j["RDI"] = vmcs->save_state()->rdi;
        j["RIP"] = vmcs->save_state()->rip;
        j["RSP"] = vmcs->save_state()->rsp;
        j["CR0"] = ::intel_x64::vmcs::guest_cr0::get();
        //j["CR2"] = ::intel_x64::cr2::get();
        j["CR3"] = ::intel_x64::vmcs::guest_cr3::get(); 
        j["CR4"] = ::intel_x64::vmcs::guest_cr4::get();
        //j["CR8"] = ::intel_x64::cr8::get();
        j["MSR_EFER"] = ::intel_x64::vmcs::guest_ia32_efer::get();
        /*//TODO:
         * DR0-DR7 debug registers
         * segment resisters
         * MSR registers
         * complete list at https://github.com/boddumanohar/libvmi/blob/master/libvmi/libvmi.h
        */
        uintptr_t addr = vmcs->save_state()->rdi;
        uint64_t size = vmcs->save_state()->rsi;

        // create memory map for the buffer in bareflank
        auto omap = bfvmm::x64::make_unique_map<char>(addr,
                    ::intel_x64::vmcs::guest_cr3::get(),
                    size
                    );

        auto &&dmp = j.dump();
        __builtin_memcpy(omap.get(), dmp.data(), size);

        bfdebug_info(0, "get-regsters vmcall handled");
    }

    void set_register(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs) {

        uintptr_t addr = vmcs->save_state()->rdi;
        uint64_t size = vmcs->save_state()->rsi;

        auto imap = bfvmm::x64::make_unique_map<char>(addr,
                    ::intel_x64::vmcs::guest_cr3::get(),
                    size
                    );

        auto ijson = json::parse(std::string(imap.get(), size));

        for (json::iterator it = ijson.begin(); it != ijson.end(); ++it) {
            if (it.key() == "RDX")
                vmcs->save_state()->rdx = it.value();
            if (it.key() == "RAX")
                vmcs->save_state()->rax = it.value();
            if (it.key() == "RBX")
                vmcs->save_state()->rbx = it.value();
            if (it.key() == "RCX")
                vmcs->save_state()->rcx = it.value();
            if (it.key() == "R08")
                vmcs->save_state()->r08 = it.value();
            if (it.key() == "R09")
                vmcs->save_state()->r09 = it.value();
            if (it.key() == "R10")
                vmcs->save_state()->r10 = it.value();
            if (it.key() == "R11")
                vmcs->save_state()->r11 = it.value();
            if (it.key() == "R12")
                vmcs->save_state()->r12 = it.value();
            if (it.key() == "R13")
                vmcs->save_state()->r13 = it.value();
            if (it.key() == "R14")
                vmcs->save_state()->r14 = it.value();
            if (it.key() == "R15")
                vmcs->save_state()->r15 = it.value();
            if (it.key() == "RBP")
                vmcs->save_state()->rbp = it.value();
            if (it.key() == "RSI")
                vmcs->save_state()->rsi = it.value();
            if (it.key() == "RDI")
                vmcs->save_state()->rdi = it.value();
            if (it.key() == "RIP")
                vmcs->save_state()->rip = it.value();
            if (it.key() == "RSP")
                vmcs->save_state()->rsp = it.value();
            /*if (it.key() == "CR0")
            ::intel_x64::cr0::set(it.value());
             if (it.key() == "CR2")
            ::intel_x64::cr2::set(it.value());
             if (it.key() == "CR3")
            ::intel_x64::cr3::set(it.value());
             if (it.key() == "CR4")
            ::intel_x64::cr4::set(it.value());
             if (it.key() == "CR8")
            		::intel_x64::cr8::set(it.value()); */
            else
                vmcs->save_state()->rdx = -1;

        }

        bfdebug_info(0, "set-register vmcall handled");
    }

    //void set_register(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs) {
    //
    //}

    void get_memmap(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs) {

	guard_exceptions([&]() {
        uintptr_t buffer = vmcs->save_state()->rdi;
        uint64_t size = 4096;

        uint64_t page = vmcs->save_state()->rbx;
        uint64_t page_shift = 12;

        uint64_t paddr = page << page_shift;

        // create memory map for physical address in bareflank
        auto omap = bfvmm::x64::make_unique_map<uintptr_t>(buffer,
                    ::intel_x64::vmcs::guest_cr3::get(),
                    size
                    );
        auto imap = bfvmm::x64::make_unique_map<uintptr_t>(paddr);
        __builtin_memcpy(omap.get(), imap.get(), size); // copy the map
	});
    }

// (dummy buffer)addr -> gpa1 -> hpa1
//                       gpa2 -> hpa2
//
// To goal is to use EPT and make addr point to gpa2 instead of gpa1.

    void get_memmap_ept(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs) {

	guard_exceptions([&]() {
        uintptr_t addr = vmcs->save_state()->rdi;

        uint64_t page = vmcs->save_state()->rbx;
        uint64_t page_shift = 12;

        gpa_t gpa2 = page<<page_shift;

	auto &&gpa2_2m = gpa2 & ~(pde::page_size_bytes - 1);
	auto &&gpa2_4k = gpa2 & ~(pte::page_size_bytes - 1);

	auto &&saddr = gpa2_2m;
	auto &&eaddr = gpa2_2m + pde::page_size_bytes;

	ept::unmap(*m_mem_map, gpa2_2m);
	for(auto i = saddr; i < eaddr; i += pte::page_size_bytes) {
		ept::identity_map_4k(*m_mem_map, i);
	}

	const auto hpa2 = m_mem_map->gpa_to_hpa(gpa2_4k);

	gpa_t gpa1 = bfvmm::x64::virt_to_phys_with_cr3(
				   addr, 
				   bfn::upper(::intel_x64::vmcs::guest_cr3::get()) 
				   );

	BFDEBUG("gpa1 %ld \n", gpa1);
	// size of gpa2 is pt::size_bytes. So to remap gpa1 to hpa2, fragment gpa1 also. 
        auto &&gpa1_2m = gpa1 & ~(pde::page_size_bytes - 1);
	auto &&gpa1_4k = gpa1 & ~(pte::page_size_bytes - 1);

	saddr = gpa1_2m;
	eaddr = gpa1_2m + pde::page_size_bytes;

	ept::unmap(*m_mem_map, gpa1_2m);
	for(auto i = saddr; i < eaddr; i += pte::page_size_bytes) {
		ept::identity_map_4k(*m_mem_map, i);
	}

	auto imap = bfvmm::x64::make_unique_map<uintptr_t>(gpa1_4k);
	ept::unmap(*m_mem_map, gpa1_4k);  // unmap the gpa before mapping it to another hpa
	ept::map_4k(*m_mem_map, gpa1_4k, hpa2); 

	});
}
	void get_paddr(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs) {

		guard_exceptions([&]() {
		
		uintptr_t buffer = vmcs->save_state()->rdi;
		gpa_t gpa = bfvmm::x64::virt_to_phys_with_cr3(
				   buffer, 
				   bfn::upper(::intel_x64::vmcs::guest_cr3::get()) 
				   );

		vmcs->save_state()->rdx = gpa;

		});
	}
	
	void test_ept(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs) {

	/*guard_exceptions([&]() {

	uintptr_t  addr1 = vmcs->save_state()->rsi; 
	uintptr_t  addr2  = vmcs->save_state()->rdi; 

	gpa_t gpa1 = bfvmm::x64::virt_to_phys_with_cr3(
				   addr1, 
				   bfn::upper(::intel_x64::vmcs::guest_cr3::get()) 
				   );

	gpa_t gpa2 = bfvmm::x64::virt_to_phys_with_cr3(
				   addr2, 
				   bfn::upper(::intel_x64::vmcs::guest_cr3::get()) 
				   );

	BFDEBUG("gpa1 %p  \n", gpa1);
	BFDEBUG("gpa2 %p  \n", gpa2);

	auto &&gpa2_2m = gpa2 & ~(pde::page_size_bytes - 1);
	auto &&gpa2_4k = gpa2 & ~(pte::page_size_bytes - 1);

	auto &&saddr = gpa2_2m;
	auto &&eaddr = gpa2_2m + pde::page_size_bytes;

	ept::unmap(*m_mem_map, gpa2_2m);

	
	for(auto i = saddr; i < eaddr; i += pte::page_size_bytes) {
		ept::identity_map_4k(*m_mem_map, i);
	}

	const auto hpa2 = m_mem_map->gpa_to_hpa(gpa2_4k);

	BFDEBUG("done remapping gpa2 \n"); 
	// size of gpa2 is pt::size_bytes. So to remap gpa1 to hpa2, fragment gpa1 also. 
        auto &&gpa1_2m = gpa1 & ~(pde::page_size_bytes - 1);
	auto &&gpa1_4k = gpa1 & ~(pte::page_size_bytes - 1);

	saddr = gpa1_2m;
	eaddr = gpa1_2m + pde::page_size_bytes;

	ept::unmap(*m_mem_map, gpa1_2m);
	for(auto i = saddr; i < eaddr; i += pte::page_size_bytes) {
		ept::identity_map_4k(*m_mem_map, i);
	}

	ept::unmap(*m_mem_map, gpa1_4k);  // unmap the gpa before mapping it to another hpa
	ept::map_4k(*m_mem_map, gpa1_4k, hpa2); 
	
	}); */

	}

    ~vcpu() = default;
};

}

// -----------------------------------------------------------------------------
// vCPU Factory
// -----------------------------------------------------------------------------

namespace bfvmm
{

std::unique_ptr<vcpu>
vcpu_factory::make_vcpu(vcpuid::type vcpuid, bfobject *obj)
{
    bfignored(obj);
    return std::make_unique<libvmi::vcpu>(vcpuid);
}

}
