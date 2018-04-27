
bits 64
default rel

section .text

global _libvmi_test_vmcall:function
_libvmi_test_vmcall:
		vmcall
		ret
