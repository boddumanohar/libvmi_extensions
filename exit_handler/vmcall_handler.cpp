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
#include <eapis/hve/arch/intel_x64/vcpu.h>

using nlohmann::json;
using namespace eapis::intel_x64;

namespace libvmi
{

gsl::not_null<ept::mmap *>
guest_mmap()
{
    bfignored(g_mm);
    static std::unique_ptr<ept::mmap> m_guest_mmap{};

    if (m_guest_mmap) {
        return m_guest_mmap.get();
    }

    m_guest_mmap = std::make_unique<ept::mmap>();

    ept::identify_map(
        m_guest_mmap.get(),
        0,
        MAX_PHYS_ADDR
    );

    return m_guest_mmap.get();
}

class vcpu : public eapis::intel_x64::vcpu
{

public:

    using handler_t = bool(gsl::not_null<bfvmm::intel_x64::vmcs *>);
    using handler_delegate_t = delegate<handler_t>;

    vcpu(vcpuid::type id) : eapis::intel_x64::vcpu{id}
    {

	this->set_eptp(
            guest_mmap()
        );

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
        else if(id == 3) {
            reremap_ept(vmcs);
        }
        else if (id == 5) {
            get_memmap_ept(vmcs);
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
        j["CR3"] = ::intel_x64::vmcs::guest_cr3::get(); 
        j["CR4"] = ::intel_x64::vmcs::guest_cr4::get();
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


// (dummy buffer)addr -> gpa1 -> hpa1
//                       gpa2 -> hpa2
//
// To goal is to use EPT and make addr point to gpa2 instead of gpa1.

    void get_memmap_ept(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs) {

	guard_exceptions([&]() {

        uint64_t addr = vmcs->save_state()->rdi;
        uint64_t page = vmcs->save_state()->rbx;

        auto gpa2 = page<<12;

	auto cr3 = intel_x64::vmcs::guest_cr3::get();
        auto gpa1 = bfvmm::x64::virt_to_phys_with_cr3(addr, cr3);

        auto gpa1_2m = bfn::upper(gpa1, ::intel_x64::ept::pd::from);
        auto gpa1_4k = bfn::upper(gpa1, ::intel_x64::ept::pt::from);
        auto gpa2_4k = bfn::upper(gpa2, ::intel_x64::ept::pt::from);

        expects(guest_mmap()->is_2m(gpa1_2m)); // failed
        guest_mmap()->unmap(gpa1_2m);

	BFDEBUG("tring identify map \n");
        ept::identify_map_4k(
            guest_mmap(),
            gpa1_2m,
            gpa1_2m + ::intel_x64::ept::pd::page_size
        );

	BFDEBUG("done identify map \n");
        auto &pte = guest_mmap()->entry(gpa1_4k);
        ::intel_x64::ept::pt::entry::phys_addr::set(pte, gpa2_4k);
	::intel_x64::vmx::invept_global(); 
	//BFDEBUG("tring identify map \n");
	/*ept::identify_map_2m(
            guest_mmap(),
            gpa1_2m,
            gpa1_2m + ::intel_x64::ept::pd::page_size
        );*/

	BFDEBUG("1 done \n");
	});
}

void reremap_ept(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs) {

	guard_exceptions([&]() {

	BFDEBUG("starting 2\n");
        uint64_t addr = vmcs->save_state()->rdi;
        uint64_t page = vmcs->save_state()->rbx;

        auto gpa2 = page<<12;

	auto cr3 = intel_x64::vmcs::guest_cr3::get();
        auto gpa1 = bfvmm::x64::virt_to_phys_with_cr3(addr, cr3);

        auto gpa1_2m = bfn::upper(gpa1, ::intel_x64::ept::pd::from);
        auto gpa1_4k = bfn::upper(gpa1, ::intel_x64::ept::pt::from);
        auto gpa2_4k = bfn::upper(gpa2, ::intel_x64::ept::pt::from);

	guest_mmap()->unmap(gpa1_4k);

	BFDEBUG("2 doing identitymap \n");
       	ept::identify_map_4k(
            guest_mmap(),
            gpa1_4k,
            gpa1_4k + ::intel_x64::ept::pt::page_size
        );

	//guest_mmap()->map_4k(gpa1_4k, gpa1_4k, attr, cache);

	auto saddr = gpa1_4k;
	auto eaddr = gpa1_4k + ::intel_x64::ept::pd::page_size;
	auto psize = 4096; /*::intel_x64::ept::pt::page_size;*/

	expects(bfn::lower(gpa1_4k, ::intel_x64::ept::pd::from) == 0); //failed 
	expects(guest_mmap()->is_4k(gpa1_4k));

	expects(bfn::lower(saddr, ::intel_x64::ept::pt::from) == 0);
	expects(bfn::lower(eaddr, ::intel_x64::ept::pt::from) == 0);


	for(auto i=saddr; i<eaddr; i+=psize){
		guest_mmap()->release(i);
	}
	
	ept::identify_map_2m(
            guest_mmap(),
            gpa1_2m,
            gpa1_2m + ::intel_x64::ept::pd::page_size
        );

	//guest_mmap()->map_2m(gpa1_4k, gpa1_4k, attr, cache);

	BFDEBUG("2 done \n");
	});
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
