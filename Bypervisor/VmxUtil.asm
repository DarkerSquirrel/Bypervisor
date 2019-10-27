.code

CaptureContext PROC
	mov [rcx], rax
	mov [rcx + 0x8], rbx
	mov [rcx + 0x10], rcx
	mov [rcx + 0x18], rdx
	mov [rcx + 0x20], rsi
	mov [rcx + 0x28], rdi
	mov [rcx + 0x30], rbp

	;; rsp contains ret
	;; [rsp + 0x8] => original rsp

	lea rax, [rsp + 0x8]
	mov [rcx + 0x38], rax

	mov [rcx + 0x40], r8
	mov [rcx + 0x48], r9
	mov [rcx + 0x50], r10
	mov [rcx + 0x58], r11
	mov [rcx + 0x60], r12
	mov [rcx + 0x68], r13
	mov [rcx + 0x70], r14
	mov [rcx + 0x78], r15

	;; Could interleave registers
	;; for a "perf boost".
	;; rax best register tho

	mov rax, dr0
	mov [rcx + 0x80], rax
	mov rax, dr1
	mov [rcx + 0x88], rax	
	mov rax, dr2
	mov [rcx + 0x90], rax	
	mov rax, dr3
	mov [rcx + 0x98], rax	
	mov rax, dr6
	mov [rcx + 0xa0], rax
	mov rax, dr7
	mov [rcx + 0xa8], rax
    
	;; Store rflags
	pushfq
	mov rax, [rsp]
	mov [rcx + 0xb0], rax
	add rsp, 8

	;; Store rip
	mov rax, [rsp]
	mov [rcx + 0xb8], rax

	mov [rcx + 0xc0], cs
	mov [rcx + 0xc8], ds
	mov [rcx + 0xd0], es
	mov [rcx + 0xd8], ss
	mov [rcx + 0xe0], fs
	mov [rcx + 0xe8], gs
	
	ret
CaptureContext ENDP

.end