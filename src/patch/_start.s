extern init

section .data
; will be initialized on program load
	_context	dd	0	; scratch variable
	.ret_addr	dd	0	; where to jmp back to
	.restore_eax	dd	0	; registers to restore prior to jumping back 
	.restore_esp	dd	0
	.restore_ebp	dd	0	

section .start alloc write exec align=4
	global _start

; should be called with a new stack, as well as rax pointing to the context
_start:
	sub		esp, 16
	mov		[esp], eax
	call 	get_addr_after
.program_offset:
	mov		[esp + 4], ebx
	mov		[esp + 8], ecx
	mov		[esp + 12], edx

	mov		ebx, eax ; actual addr of .program_offset
	add		eax, _context - .program_offset ; actual addr of _context
	add		ebx, jmp_back - .program_offset	; actual addr of jmp_back

	mov 	ecx, [esp] 	; original value of eax
	mov		[eax + 8], ecx ; move original eax into restore_eax

	call 	init	; call the c code, will not change any registers (calling convention)

	; to return with all of the registers restored, we need to
	; write the jmp_back addr as the last instruction
	; jmp_to - label - (jmp instr len) 
	mov 	ecx, [eax + 4] ; jmp_to_addr
	sub		ecx, ebx
	sub		ecx, 5	; ecx contains offset to jump to

	mov		dl, 0xE9
	mov		byte [ebx], dl	; rel jmp
	mov		dword [ebx + 1], ecx

	; restore registers
	mov		ebx, [esp + 4]
	mov		ecx, [esp + 8]
	mov		edx, [esp + 12]

	mov		esp, [eax + 12]
	mov		ebp, [eax + 16]
	mov		eax, [eax + 8]

	; jump back to where it came from, the state is the exact same
jmp_back:
	nop
	nop
	nop

	nop
	nop

	; puts the calling address in ecx
get_addr_after:
	pop		eax	; pop to view the return addr
	push	eax	; put the return address back
	ret

