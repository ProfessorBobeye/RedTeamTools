.code

EXTERN SW2_GetSyscallNumber: PROC

NtWaitForSingleObject PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 078599045h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtWaitForSingleObject ENDP

NtClose PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0059596A8h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtClose ENDP

NtAllocateVirtualMemory PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0CFD224B0h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAllocateVirtualMemory ENDP

NtFreeVirtualMemory PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 00F92E2C4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtFreeVirtualMemory ENDP

NtProtectVirtualMemory PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0F548E1C5h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtProtectVirtualMemory ENDP

NtCreateThreadEx PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 03AA6181Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateThreadEx ENDP

end