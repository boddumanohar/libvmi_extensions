#include<stdio.h>
#include<stdint.h>
#include "vm_event.h"
#include<stdlib.h>

int main() {
		
	vm_event_request_t *new =  malloc(sizeof(vm_event_request_t ));
	printf("The return val is %p \n", new);

	asm("movq $0, %0"
			:"=d"(new)
			);
	asm("movl $2, %eax");
	asm("vmcall");

	printf("The return val is %p \n", new);
	return 0;
}
