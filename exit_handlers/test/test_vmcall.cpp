//
// Bareflank Extended APIs
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
#include <bfjson.h>

namespace libvmi
{

class vcpu : public bfvmm::intel_x64::vcpu
{
public:

    using handler_t = bool(gsl::not_null<bfvmm::intel_x64::vmcs *>);
    using handler_delegate_t = delegate<handler_t>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param ??
    ///
    vcpu(vcpuid::type id) : bfvmm::intel_x64::vcpu{id}
    {
        exit_handler()->add_handler(
						intel_x64::vmcs::exit_reason::basic_exit_reason::vmcall,
            handler_delegate_t::create<vcpu, &vcpu::vmcall_handler>(this)
        );
    }

			bool vmcall_handler(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs) {
				//hypercall 1 = test bareflank status
				/*uint64_t id = vmcs->save_state()->rax; 
			  if (id == 1) {
					bfdebug_info(0, "vmcall handled");
				}

				if (id == 2) { */
					//get_register_data(vmcs);

					bfdebug_info(0, "gettting register data");
					json j;
					j["rax"] =  vmcs->save_state()->rax;
					j["rbx"] =  vmcs->save_state()->rbx;
					j["rcx"] =  vmcs->save_state()->rcx;
					j["rdx"] =  vmcs->save_state()->rdx;
					j["rsi"] =  vmcs->save_state()->rsi;
					j["rdi"] =  vmcs->save_state()->rdi; 
					j["rsp"] =  vmcs->save_state()->rsp;
					j["rbp"] =  vmcs->save_state()->rbp;
					j["rip"] =  vmcs->save_state()->rip;
					j["r08"] =  vmcs->save_state()->r08;
					j["r09"] =  vmcs->save_state()->r09;
					j["r10"] =  vmcs->save_state()->r10;
					j["r11"] =  vmcs->save_state()->r11;
					j["r12"] =  vmcs->save_state()->r12;
					j["r13"] =  vmcs->save_state()->r13;
					j["r14"] =  vmcs->save_state()->r14;
					j["r15"] =  vmcs->save_state()->r15;

					std::string str = j.dump();
					const char *cstr = str.c_str();
					_putin_eax(cstr);

			//}

				return advance(vmcs);
			}

			void get_register_data(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs) {

        bfdebug_info(0, "gettting register data");
				uint64_t ptr1 = vmcs->save_state()->rdx;
				vm_event_response_t *ptr = (vm_event_response_t *)ptr1;

				if(ptr == NULL) {
					bfdebug_info(0, "ptr is null");
				}

				ptr->version = 0;
				ptr->reason = VM_EVENT_REGISTER; 
				ptr->vcpuid = 1;
				ptr->u.x86.rcx =  vmcs->save_state()->rcx;
				ptr->u.x86.rdx =  vmcs->save_state()->rdx;
				ptr->u.x86.rbx =  vmcs->save_state()->rbx;
				ptr->u.x86.rsp =  vmcs->save_state()->rsp;
				ptr->u.x86.rbp =  vmcs->save_state()->rbp;
				ptr->u.x86.rsi =  vmcs->save_state()->rsi;
				ptr->u.x86.rdi =  vmcs->save_state()->rdi;

		}

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
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
