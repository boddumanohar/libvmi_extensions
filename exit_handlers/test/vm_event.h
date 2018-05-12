// the request response for the event. 

// reason for vm-event

#define VM_EVENT_REGISTER 1 << 1

#define VM_EVENT_MEMORY 1 << 2


struct vm_event_regs_x86 {
     uint64_t rax;
     uint64_t rcx;
     uint64_t rdx;
     uint64_t rbx;
     uint64_t rsp;
     uint64_t rbp;
     uint64_t rsi;
     uint64_t rdi;
     uint64_t r8;
     uint64_t r9;
		 uint64_t r10;
		 uint64_t r11;
		 uint64_t r12;
     uint64_t r13;
     uint64_t r14;
     uint64_t r15;
     uint64_t rflags;
     uint64_t dr7;
     uint64_t rip;
     uint64_t cr0;
     uint64_t cr2;
     uint64_t cr3;
     uint64_t cr4;
     uint64_t sysenter_cs;
     uint64_t sysenter_esp;
     uint64_t sysenter_eip;
     uint64_t msr_efer;
     uint64_t msr_star;
     uint64_t msr_lstar;
     uint64_t fs_base;
     uint64_t gs_base;
     uint32_t cs_arbytes;
		 uint32_t _pad;
};

typedef struct vm_event {
	uint32_t version;
	uint32_t reason;
	uint32_t vcpuid;
	
	union{
		struct vm_event_regs_x86 x86;
	}u;
}vm_event_request_t, vm_event_response_t;

	
	
