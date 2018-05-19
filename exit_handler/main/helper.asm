bits 64
default rel

section .text

global _putin_eax:function
_putin_eax:
    push rbx
		mov eax, edi
    pop rbx
    ret
