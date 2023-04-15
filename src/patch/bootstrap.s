extern init

section .data
; will be initialized on program load
; order matters
	_context	dq	0	; scratch variable
	ret_addr	dq	0	; where to jmp back to
	restore_esp	dq	0
	restore_ebp	dq	0	
; end order matters

; these are passed to the c program, as a pointer to a structure
; therefore order matters
    arg_kernel32  dq  0 ; must be the first item in the struct
    arg_lol_module     dq 0
    arg_swap_return    dq 0
    arg_seg_table_addr   dq  0
    arg_path_root   dq  0

    var_call_count          dq 0
    var_expected_return_addr    dq 0
    var_original_jump_addr      dq 0
    var_fn_ptr_addr             dq 0
; end order matters

; it is not safe to push items
; to the stack while executing swap_return
; because they might be relying on some values, so use these instead
    scratch0    dq 0     
    scratch1    dq 0     
    scratch2    dq 0     
    scratch3    dq 0     

    path_root_buf   times 1024 db 0         

section .start alloc write exec align=8
	global _start

; should be called with a new stack, as well as rax pointing to the context
_start:
	sub		rsp, 32	; keep 16 byte aligned
	mov		[rsp], rax
	mov		[rsp + 8], rbx
	mov		[rsp + 16], rcx
	mov		[rsp + 24], rdx

	call	rwx_get_runtime_offset ; moves the value of runtime_offset into eax

    ; move a pointer to path_root_buf into path_root
    lea     rcx, [rax - rwx_runtime_offset + path_root_buf]
    mov     [rax - rwx_runtime_offset + arg_path_root], rcx

    mov     rcx, [rax - rwx_runtime_offset + ret_addr] ; moves ret addr into rcx
    mov     [rax - rwx_runtime_offset + .jmp_back_to], rcx ; mov ret addr into .jmp_back_to

    mov     rcx, rax ; save rwx_runtime_offset to rcx

	call	locate_kernel32 ; moves the address of kernel32 into eax
    mov     [rcx - rwx_runtime_offset + arg_kernel32], rax

    call    locate_lol_module ; moves to init agrs
    mov     [rcx - rwx_runtime_offset + arg_lol_module], rax

	lea		rax, [rcx - rwx_runtime_offset + swap_return] ; move the addr of swap_return for param
    mov     [rcx - rwx_runtime_offset + arg_swap_return], rax

    ; set ecx to the pointer to the init args struct
    lea     rcx, [rcx - rwx_runtime_offset + arg_kernel32]
	call 	init	; call the c code, will not change any registers (calling convention)

	call	rwx_get_runtime_offset ; moves the value of runtime_offset into eax
	add		rax, _context - rwx_runtime_offset ; actual addr of _context

	mov 	rcx, [rsp] 	; original value of eax
	mov		[rax], rcx ; move original eax into _context to be restored

	; restore registers saved on stack
	mov		rbx, [rsp + 8]
	mov		rcx, [rsp + 16]
	mov		rdx, [rsp + 24]

    ; restore registers from the context given from the loader
	mov		rsp, [rax + 16]
	mov		rbp, [rax + 24]

    ; restore rax from its place at _context
	mov		rax, [rax]  

    ; the state is exactly as it was prior to changing anything
    ; jump to whatever address is stored in jmp_back_to. This is needed because
    ; we can not use any stack memory or registers because the state needs to be
    ; restored to the exact state it was prior
    jmp     QWORD [rel .jmp_back_to]

    ; we need to store the address to jump back to here, because it will be
    ; jumped to by the previous instruction
.jmp_back_to:
	nop
	nop
	nop
	nop
	nop
	nop
    nop
    nop

; go through the windows thread environment block to find the kernel32 module
; https://www.ired.team/offensive-security/code-injection-process-injection/finding-kernel32-base-and-function-addresses-in-shellcode
; https://nytrosecurity.com/2019/06/30/writing-shellcodes-for-windows-x64/
locate_kernel32:
    xor rax, rax            ; reset rax
    mov rax, [gs:rax + 60h] ; rax = PEB
    mov rax, [rax + 18h]    ; rax = PEB->Ldr
    mov rax, [rax + 20h]    ; rsi = PEB->Ldr.InMemOrder
    mov rax, [rax]          ; this program's module
    mov rax, [rax]          ; ntdll
    mov rax, [rax + 20h]    ; kernel32 base address    
    ret

locate_lol_module:
    xor rax, rax            ; reset rax
    mov rax, [gs:rax + 60h] ; rax = PEB
    mov rax, [rax + 18h]    ; rax = PEB->Ldr
    mov rax, [rax + 20h]    ; rsi = PEB->Ldr.InMemOrder
    mov rax, [rax + 20h]    ; this program's base address
    ret

rwx_get_runtime_offset:
    call    runtime_offset
rwx_runtime_offset:
    pop     rax
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
    pop     rax
    ret

swap_return:
    ; eax was used for the jump, so it is free to use
    ; returns actual address of runtime_offset into eax
    call    get_runtime_offset

    ; save the registers to be restored later
    mov     [rax - runtime_offset + scratch0], rbx
    mov     [rax - runtime_offset + scratch1], rcx
    mov     [rax - runtime_offset + scratch2], rdx
    mov     [rax - runtime_offset + scratch3], rsi

    mov     rbx, [rax - runtime_offset + var_expected_return_addr] ; ebx is the expected_return
    mov     rcx, rsp ; initialzie at the bottom of the stack (4 down is first return addr)
    mov     rsi, rsp
    add     rsi, 200 ; 50 possible addresses down the stack

.test_ptr:
    cmp     rcx, rsi 
    je      .finish ; it reached the bottom without changing the value

    add     rcx, 8 ; move down the stack to the next ptr
    mov     rdx, [rcx]
    cmp     rbx, rdx ; expected_return_addr == esp[i]
    jne     .test_ptr  ; try with the next value
.success:
    ; replace return address with the address of return_1_to_expected_return 
    mov     rdx, rax
    add     rdx, return_1_to_expected_return - runtime_offset
    mov     [rcx], rdx  
    
.finish:
    mov     rsi, [rax - runtime_offset + scratch3]
    mov     rdx, [rax - runtime_offset + scratch2]
    mov     rcx, [rax - runtime_offset + scratch1]
    mov     rbx, [rax - runtime_offset + scratch0]

    ; go back to where it was supposed to go in the first place
    mov     rax, [rax - runtime_offset + var_original_jump_addr]
    jmp     rax 

; this function will be returned to instead of the caller
; so it can go in and hot patch the value
return_1_to_expected_return:
    ; eax is useable because it will be overwritten anyways
    ; eax contains the actual address of runtime_offset
    call    get_runtime_offset

    push    rbx
    push    rcx

    mov     rbx, [rax - runtime_offset + var_call_count] 
    inc     rbx
    mov     [rax - runtime_offset + var_call_count], rbx

    pop     rcx
    pop     rbx

    ; push return addr so when ret instruction is hit, it jumps back to this addr
    mov     rax, [rax - runtime_offset + var_expected_return_addr]
    push    rax

    ; set eax to 1 (true)
    xor     rax, rax
    inc     rax

    ret
