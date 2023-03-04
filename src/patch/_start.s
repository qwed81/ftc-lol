extern init

section .data
	_context	dd	0, 0

section .text
	global _start

_start:
	call 	init	; call the c code, will not change any registers

	; eax will have a ptr to (ret_addr, eax_state) 
	push	[eax]	; setup the address for ret
	mov		eax, [eax + 4] ; restore the state of eax
	ret 

