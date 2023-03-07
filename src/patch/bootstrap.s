extern init

section .data
; will be initialized on program load
	_context	dd	0	; scratch variable
	.ret_addr	dd	0	; where to jmp back to
	.restore_esp	dd	0
	.restore_ebp	dd	0	

section .start alloc write exec align=4
	global _start

; should be called with a new stack, as well as rax pointing to the context
_start:
	sub		esp, 16	; keep 16 byte aligned
	mov		[esp], eax
	mov		[esp + 4], ebx
	mov		[esp + 8], ecx
	mov		[esp + 12], edx

	call	locate_kernel32 ; moves the address of kernel32 into eax
	mov		ecx, eax	; conform to fastcall calling convention
	call 	init	; call the c code, will not change any registers (calling convention)

	call 	.get_addr_after
.program_offset:
	mov		ebx, eax ; actual addr of .program_offset
	add		eax, _context - .program_offset ; actual addr of _context
	add		ebx, .jmp_back - .program_offset	; actual addr of jmp_back

	mov 	ecx, [esp] 	; original value of eax
	mov		[eax], ecx ; move original eax into restore_eax

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

	mov		esp, [eax + 8]
	mov		ebp, [eax + 12]
	mov		eax, [eax]

	; jump back to where it came from, the state is the exact same
.jmp_back:
	nop
	nop
	nop
	nop
	nop

	; puts the calling address in ecx
.get_addr_after:
	pop		eax	; pop to view the return addr
	push	eax	; put the return address back
	ret

; go through the windows thread environment block to find the kernel32 module
; https://www.ired.team/offensive-security/code-injection-process-injection/finding-kernel32-base-and-function-addresses-in-shellcode
locate_kernel32:
	mov eax, [fs:30h]		    ; Pointer to PEB (https://en.wikipedia.org/wiki/Win32_Thread_Information_Block)
	mov eax, [eax + 0ch]		; Pointer to Ldr
	mov eax, [eax + 14h]		; Pointer to InMemoryOrderModuleList
	mov eax, [eax]				  ; this program's module
	mov eax, [eax]				  ; ntdll module
	mov eax, [eax -8h + 18h]	; kernel32.DllBase
	ret
