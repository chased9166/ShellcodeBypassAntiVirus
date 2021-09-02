option casemap : none
.data
EXTERN SBAV_NtAllocateVirtualMemorySyscallNumber : DWORD
.code
SBAV_NtAllocateVirtualMemory PROC
mov eax, SBAV_NtAllocateVirtualMemorySyscallNumber
push rcx
pop r10
syscall
ret
SBAV_NtAllocateVirtualMemory ENDP
END
