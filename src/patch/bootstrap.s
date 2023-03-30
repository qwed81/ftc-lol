extern init

section .data
; will be initialized on program load
	_context	dd	0	; scratch variable
	.ret_addr	dd	0	; where to jmp back to
	.restore_esp	dd	0
	.restore_ebp	dd	0	

; these are passed to the c program, as a pointer to a structure
; therefore order matters
    arg_kernel32  dd  0
    arg_lol_module     dd 0
    arg_swap_return    dd 0

    var_call_count          dd 0
    var_expected_return_addr    dd 0
    var_original_jump_addr      dd 0
    var_fn_ptr_addr             dd 0
; end order matters


section .start alloc write exec align=4
	global _start

; should be called with a new stack, as well as rax pointing to the context
_start:
	sub		esp, 16	; keep 16 byte aligned
	mov		[esp], eax
	mov		[esp + 4], ebx
	mov		[esp + 8], ecx
	mov		[esp + 12], edx

	call	rwx_get_runtime_offset ; moves the value of runtime_offset into eax
    mov     ecx, eax

	call	locate_kernel32 ; moves the address of kernel32 into eax
    mov     [ecx - rwx_runtime_offset + arg_kernel32], eax

    call    locate_lol_module ; moves to init agrs
    mov     [ecx - rwx_runtime_offset + arg_lol_module], eax

	lea		eax, [ecx - rwx_runtime_offset + swap_return] ; move the addr of swap_return for param
    mov     [ecx - rwx_runtime_offset + arg_swap_return], eax

    ; set ecx to the pointer to the init args struct
    lea     ecx, [ecx - rwx_runtime_offset + arg_kernel32]
	call 	init	; call the c code, will not change any registers (calling convention)

	call	rwx_get_runtime_offset ; moves the value of runtime_offset into eax

	mov		ebx, eax ; actual addr of .program_offset
	add		eax, _context - rwx_runtime_offset ; actual addr of _context
	add		ebx, .jmp_back - rwx_runtime_offset	; actual addr of jmp_back

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

locate_lol_module:
	mov eax, [fs:30h]		    ; Pointer to PEB (https://en.wikipedia.org/wiki/Win32_Thread_Information_Block)
	mov eax, [eax + 0ch]		; Pointer to Ldr
	mov eax, [eax + 14h]		; Pointer to InMemoryOrderModuleList
	mov eax, [eax - 8h + 18h]	; this program's module DllBase
    ret


rwx_get_runtime_offset:
    call    runtime_offset
rwx_runtime_offset:
    pop     eax
    ret

; the game has a function pointer that is used while checking
; if a value is valid. Because this function pointer is not constant
; we can replace the value of this pointer ourself, and then when it is
; jumped to, we can jump back to what was supposed to be called. This is important
; because we can then look back in the stack, and change the return address all the
; way down the stack to our own function, that can then intercept it, and change the return
; value to true in all cases, skipping their ability to validate
; idea inspired by https://github.com/LeagueToolkit/cslol-manager
section .text

get_runtime_offset:
    call    runtime_offset
runtime_offset:
    pop     eax
    ret

swap_return:
    ; eax was used for the jump, so it is free to use
    push    ebx
    push    ecx 
    push    edx
    push    esi

    ; returns actual address of runtime_offset into eax
    call    get_runtime_offset

    mov     ebx, [eax - runtime_offset + var_expected_return_addr] ; ebx is the expected_return
    mov     ecx, esp ; initialzie at the bottom of the stack (4 down is first return addr)
    mov     esi, esp
    add     esi, 200 ; 10 possible addresses down the stack
.test_ptr:
    cmp     ecx, esi 
    je      .finish ; it reached the bottom without changing the value

    add     ecx, 4 ; move down the stack to the next ptr
    mov     edx, [ecx]
    cmp     ebx, edx ; expected_return_addr == esp[i]
    jne     .test_ptr  ; try with the next value
.success:
    ; replace return address with the address of return_1_to_expected_return 
    mov     edx, eax
    add     edx, return_1_to_expected_return - runtime_offset
    mov     [ecx], edx  
    
    ; change back the addr of original fn pointer so it is not hooked anymore
    ; it does not need to be hooked assuming our swapped return address is in place
    ; also this is good measure to fight against recursion 
    ; (as the fn ptr might call itself, and then checked with if statement)
    ; mov     ebx, [eax - runtime_offset + fn_ptr_addr]
    ; mov     ecx, [eax - runtime_offset + original_jump_addr]
    ; mov     [ebx], ecx
.finish:
    pop     esi
    pop     edx
    pop     ecx
    pop     ebx

    ; go back to where it was supposed to go in the first place
    mov     eax, [eax - runtime_offset + var_original_jump_addr]
    jmp     eax 

; this function will be returned to instead of the caller
; so it can go in and hot patch the value
return_1_to_expected_return:
    ; eax is useable because it will be overwritten anyways
    ; eax contains the actual address of runtime_offset
    call    get_runtime_offset

    push    ebx
    push    ecx

    mov     ebx, [eax - runtime_offset + var_call_count] 
    inc     ebx
    mov     [eax - runtime_offset + var_call_count], ebx

    ; need to reinstall the hook as the next time the return value will not be stopped
    ; mov     ebx, [eax - runtime_offset + fn_ptr_addr]
    ; mov     ecx, [eax - runtime_offset + swap_return]
    ; mov     [ebx], ecx

    pop     ecx
    pop     ebx

    ; push return addr so when ret instruction is hit, it jumps back to this addr
    mov     eax, [eax - runtime_offset + var_expected_return_addr]
    push    eax

    ; set eax to 1 (true)
    xor     eax, eax
    inc     eax

    ret
