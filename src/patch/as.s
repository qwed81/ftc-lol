extern expected_return_addr
extern original_jump_addr
extern fn_ptr_addr
extern call_count

extern log_int

get_runtime_offset:
    call    runtime_offset
runtime_offset:
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
    global  swap_return
    global  get_runtime_offset
    global  runtime_offset

swap_return:
    ; eax was used for the jump, so it is free to use
    push    ebx
    push    ecx 
    push    edx
    push    esi

    ; returns actual address of runtime_offset into eax
    call    get_runtime_offset

    mov     ebx, [eax - runtime_offset + expected_return_addr] ; ebx is the expected_return
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
    mov     eax, [eax - runtime_offset + original_jump_addr]
    jmp     eax 

; this function will be returned to instead of the caller
; so it can go in and hot patch the value
return_1_to_expected_return:
    ; eax is useable because it will be overwritten anyways
    ; eax contains the actual address of runtime_offset
    call    get_runtime_offset

    push    ebx
    push    ecx

    mov     ebx, [eax - runtime_offset + call_count] 
    inc     ebx
    mov     [eax - runtime_offset + call_count], ebx

    ; need to reinstall the hook as the next time the return value will not be stopped
    ; mov     ebx, [eax - runtime_offset + fn_ptr_addr]
    ; mov     ecx, [eax - runtime_offset + swap_return]
    ; mov     [ebx], ecx

    pop     ecx
    pop     ebx

    ; push return addr so when ret instruction is hit, it jumps back to this addr
    mov     eax, [eax - runtime_offset + expected_return_addr]
    push    eax

    ; set eax to 1 (true)
    xor     eax, eax
    inc     eax

    ret


