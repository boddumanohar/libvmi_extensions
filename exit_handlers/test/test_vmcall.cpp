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
//#include <bfjson.h>
//#include <json-c/json.h>

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
				uint64_t id = vmcs->save_state()->rax; 
			  if (id == 1) {
					bfdebug_info(0, "vmcall handled");
				}
				if (id == 2) { 
					get_register_data(vmcs);
				}
					return advance(vmcs);
			}

			void get_register_data(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs){
					bfdebug_info(0, "gettting register data");
					BFDEBUG(" rax %ld ", vmcs->save_state()->rax);

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
