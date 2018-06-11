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
#include <bfvmm/memory_manager/arch/x64/map_ptr.h>
#include "json.hpp"
#include <stdlib.h>
#include <string.h>

using nlohmann::json;
namespace libvmi
{

	class vcpu : public bfvmm::intel_x64::vcpu
	{
		public:

			using handler_t = bool(gsl::not_null<bfvmm::intel_x64::vmcs *>);
			using handler_delegate_t = delegate<handler_t>;

			vcpu(vcpuid::type id) : bfvmm::intel_x64::vcpu{id}
			{
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
				return advance(vmcs);
			}

			void get_register_data(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs){
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
				j["CR0"] = ::intel_x64::cr0::get();
				j["CR2"] = ::intel_x64::cr2::get();
				j["CR3"] = ::intel_x64::cr3::get();
				j["CR4"] = ::intel_x64::cr4::get();
				j["CR8"] = ::intel_x64::cr8::get();
				//::intel_x64::vmcs::guest_ia32_efer::lma::disable();
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
						size, 
						::intel_x64::vmcs::guest_ia32_pat::get());

				auto &&dmp = j.dump();
				__builtin_memcpy(omap.get(), dmp.data(), size);

				bfdebug_info(0, "get-regsters vmcall handled");
			}

			void set_register(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs) {

				uintptr_t addr = vmcs->save_state()->rdi;
				uint64_t size = vmcs->save_state()->rsi;

				auto imap = bfvmm::x64::make_unique_map<char>(addr, 
						::intel_x64::vmcs::guest_cr3::get(), 
						size, 
						::intel_x64::vmcs::guest_ia32_pat::get());

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

				uintptr_t addr = vmcs->save_state()->rdi;
				uint64_t size = 4096; 

				uint64_t page = vmcs->save_state()->rbx;
				uint64_t page_shift = 12;

				uint64_t paddr = page<<page_shift;
				
				// create memory map for the buffer in bareflank
				auto omap = bfvmm::x64::make_unique_map<void>(addr, 
						::intel_x64::vmcs::guest_cr3::get(), 
						size, 
						::intel_x64::vmcs::guest_ia32_pat::get());

				auto imap = bfvmm::x64::make_unique_map<void>(paddr); 

				__builtin_memcpy(omap.get(), imap.get(), size);

				//BFDEBUG("the value after is copy is %ld \n", omap.get()[0]);
				//uint64_t pml4_value = omap.get()[0];

				//BFDEBUG("pml4_value is %ld \n", pml4_value);
				//uint64_t pdpte_location = pml4e_value & VMI_BIT_MASK(12,51);

				/*for (int i = 0;i < 10; i++) {
					auto pml4_pte = bfvmm::x64::page_table_entry{&imap.get()[i]};
					BFDEBUG("pml4_pte is %ld \n", pml4_pte.phys_addr());
				}*/

				BFDEBUG("DONE\n");
				 /*from = ::x64::page_table::pdpt::from;
				 auto pdpt_idx = ::x64::page_table::index(current_virt, from);
				 auto pdpt_map = bfvmm::x64::make_unique_map<uintptr_t>(pml4_pte.phys_addr());
				 auto pdpt_pte = bfvmm::x64::page_table_entry{&pdpt_map.get()[pdpt_idx]};

				 BFDEBUG("pdpte_location %ld \n", pdpt_pte.phys_addr());  */

				imap.release();
				//omap.release();
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
