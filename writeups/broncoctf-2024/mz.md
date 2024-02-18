---
description: reversing, windows, DOS, x86
---

# MZ

### Description

Can you reveal the secrets hidden within this binary?

(Note: this is a Windows executable, but it's been saved with a .BIN extension to avoid antivirus problems. You will need to replace .BIN with .EXE to run it.)

Target Difficulty: Medium

{% file src="../../.gitbook/assets/mz.bin" %}

### Let's reverse it!

```
$ file mz.bin
mz.bin: PE32 executable (console) Intel 80386, for MS Windows
```

We are given a 32 bit windows Executable.\
Throwing it into ghidra, after a bit of reverse engineering, we can see that it just does some normal windows initialization stuff and then prints "Nothing here :-)".\


<figure><img src="../../.gitbook/assets/image (7).png" alt=""><figcaption><p>Only code that is not default windows stuff.</p></figcaption></figure>

So it seems like there is nothing there?\
To make sure I threw it into WinDBG and dumped the memory before the binary exited and it did not contain anything interesting.\
So where is the flag?

### Taking a step back

If there is no interesting code that is executed, maybe the binary contains something else hidden inside?\
Let's try some tools and see what we find:

{% code fullWidth="false" %}
```
$ binwalk mz.bin 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Microsoft executable, portable (PE)

$ # shorter strings were also uninteresting
$ strings -n 20 mz.bin
`local static guard'
`vector deleting destructor'
`default constructor closure'
`scalar deleting destructor'
`vector constructor iterator'
`vector destructor iterator'
`vector vbase constructor iterator'
`virtual displacement map'
`eh vector constructor iterator'
`eh vector destructor iterator'
`eh vector vbase constructor iterator'
`copy constructor closure'
`local vftable constructor closure'
`placement delete closure'
`placement delete[] closure'
`managed vector constructor iterator'
`managed vector destructor iterator'
`eh vector copy constructor iterator'
`eh vector vbase copy constructor iterator'
`dynamic initializer for '
`dynamic atexit destructor for '
`vector copy constructor iterator'
`vector vbase copy constructor iterator'
`managed vector copy constructor iterator'
`local static thread guard'
 Base Class Descriptor at (
 Class Hierarchy Descriptor'
 Complete Object Locator'
`anonymous namespace'
`template-parameter-
`non-type-template-parameter
`template-type-parameter-
`generic-class-parameter-
`generic-method-parameter-
`local static destructor helper'
`template static data member constructor helper'
`template static data member destructor helper'
InitializeCriticalSectionEx
 !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~
 !"#$%&'()*+,-./0123456789:;<=>?@abcdefghijklmnopqrstuvwxyz[\]^_`abcdefghijklmnopqrstuvwxyz{|}~
 !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`ABCDEFGHIJKLMNOPQRSTUVWXYZ{|}~
GetEnabledXStateFeatures
GetProcessWindowStation
GetSystemTimePreciseAsFileTime
GetUserDefaultLocaleName
GetUserObjectInformationW
GetXStateFeaturesMask
AppPolicyGetProcessTerminationMethod
AppPolicyGetThreadInitializationType
AppPolicyGetShowDeveloperDiagnostic
AppPolicyGetWindowingModel
SetThreadStackGuarantee
C:\Users\azhan\workspace\broncoctf-challenges\mz.pdb
                          
abcdefghijklmnopqrstuvwxyz
ABCDEFGHIJKLMNOPQRSTUVWXYZ
                          
abcdefghijklmnopqrstuvwxyz
ABCDEFGHIJKLMNOPQRSTUVWXYZ
.?AVbad_exception@std@@
.?AVDNameStatusNode@@
QueryPerformanceCounter
GetSystemTimeAsFileTime
UnhandledExceptionFilter
SetUnhandledExceptionFilter
IsProcessorFeaturePresent
InterlockedPushEntrySList
InterlockedFlushSList
EnterCriticalSection
LeaveCriticalSection
DeleteCriticalSection
InitializeCriticalSectionAndSpinCount
GetEnvironmentStringsW
FreeEnvironmentStringsW
SetEnvironmentVariableW
SetConsoleCtrlHandler
0#0*01080?0F0M0T0\0d0l0x0
2080>0D0J0P0V0\0b0h0n0t0
3$3*30363<3B3H3N3T3Z3`3f3l3r3x3~3
4#4'4+4/43474;4?4C4G4K4O4S4W4[4_4c4g4k4o4s4w4{4
6"6&6*6.62666:6>6B6F6J6N6R6V6Z6^6b6f6j6n6r6v6z6~6
6 6$64989@:P>T>\>`>h>p>x>
? ?(?0?8?@?H?P?X?`?h?p?x?
0 0(00080@0H0P0X0`0h0p0x0
1 1(10181@1H1P1X1`1h1p1x1
1P>T>X>\>`>h>l>p>t>x>
1024282<2@2D2H2L2P2T2X2\2`2d2h2l2p2t2x2|2
3 3$3(3,3034383<3@3D3H3L3P3T3X3\3`3d3h3l3p3t3x3|3
2 2$2(2,2024282<2@2D2H2L2P2T2X2\2`2d2
=$=,=4=<=D=L=T=\=d=l=t=|=
>$>,>4><>D>L>T>\>d>l>t>|>
?$?,?4?<?D?L?T?\?d?l?t?|?
0$0,040<0D0L0T0\0d0l0t0|0
1$1,141<1D1L1T1\1d1l1t1|1
2$2,242<2D2L2T2\2d2l2t2|2
3$3,343<3D3L3T3\3d3l3
 1(10181@1H1P1X1`1h1p1x1
2 2(20282@2H2P2X2`2h2p2x2
3 3(30383@3H3P3X3`3h3p3x3
4 4(40484@4H4P4X4`4h4p4x4
5 5(50585@5H5P5X5`5h5p5x5
6 6(60686@6H6P6X6`6h6p6x6
7 7(70787@7H7P7X7`7h7p7x7
>$>,>4><>D>L>T>\>d>l>t>|>
```
{% endcode %}

There seems to be nothing there.\
At least nothing obvious.\
However, there is something that is usually there that is missing!

### This program cannot be run in DOS mode

_The following section contains a bit of hearsay, so it may not be 100% correct. But the gist should be!_

At some point in the past, Microsoft switched from DOS to a more modern operating system. With that came some big changes such that many applications developed for the newer systems were no longer compatible with DOS.\
However, people that were still using DOS and accidentally got a program that was too recent and not compatible should be notified in some way.\
And, programs that want to remain backward compatible should be able to embed some code that will be executed on DOS systems when running the exact same executable.\
So the executable format was fixed in a bit of a hacky way:\
A PE executable has a header that still works fine on DOS and actually contains a short snippet of 16-bit x86 code that will be run on DOS.\
However, if the same application is executed on more recent operating systems (say Windows), the PE header contains additional information on how to run an actual 32-bit or 64-bit x86 application.\
Nowadays, most PE executables are built for windows and are incompatible with DOS.\
But this part in the header remains.\
Usually, it is filled with some code printing the string "This program cannot be run in DOS mode".\
Basically, the code just puts the address of the string into a register and then does a syscall printing the string.\
Thus, the string is also contained in the code snippet.\
...\
But it is missing in the binary we are given!\
So what is _actually_ contained in the DOS code part thingy of the header?

### Getting the flag (easy mode)

The easiest way to find out what the program does in DOS is to just execute it in DOS.\
For this we can use DOSBox.\
First, we rename mz.bin to mz.exe such that it is detected as executable. Then (note that DOSbox always uses an US keyboard layout.):

```
$ sudo apt install dosbox
$ dosbox
Z:> MOUNT C /path/to/folder/containing/mz.exe/
Drive C is mounted as local directory /path/to/folder/containing/mz.exe/

Z:> C:

C:> MZ
bronco{th1s_pr0gr4m_c4n_b3_run_1n_D0S_m0d3}
```

Yey, we got the flag!\
But what does the code _actually_ do?

### Looking at the header&#x20;

Let's take a look at the code in the header using Ghidra:\


<figure><img src="../../.gitbook/assets/image (8).png" alt=""><figcaption><p>Click on "Headers" in the "Program Trees" view to get to the header.</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (9).png" alt=""><figcaption><p>The interesting part of the header is the "e_program" field, which contains an actual DOS program.</p></figcaption></figure>

To better work with this field, I expanded it in ghidra.\
When marking the whole array, we can `right click` -> `copy special ...` -> `Python Byte String` to get the data as nice python bytestring into the clipboard:

{% code overflow="wrap" %}
```
b'\x0e\x1f\xba\x22\x00\x31\xdb\x83\xfb\x2b\x74\x0d\x8a\x87\x22\x00\x34\xf7\x88\x87\x22\x00\x43\xeb\xee\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21\x95\x85\x98\x99\x94\x98\x8c\x83\x9f\xc6\x84\xa8\x87\x85\xc7\x90\x85\xc3\x9a\xa8\x94\xc3\x99\xa8\x95\xc4\xa8\x85\x82\x99\xa8\xc6\x99\xa8\xb3\xc7\xa4\xa8\x9a\xc7\x93\xc4\x8a\x0d\x0d\x0a\x24\x0d\x23\x9e\x78\x66\x20\x9f\x66\x0d\x25\x9e\xfc\x66\x20\x9f\x66\x0d\x24\x9e\x60\x66\x20\x9f\x66\x0d\x21\x9e\x71\x66\x20\x9f\x72\x66\x21\x9f\x22\x66\x20\x9f\x20\x13\x25\x9e\x57\x66\x20\x9f\x20\x13\x24\x9e\x63\x66\x20\x9f\x20\x13\x23\x9e\x63\x66\x20\x9f\xb1\x13\x24\x9e\x73\x66\x20\x9f\xb1\x13\x22\x9e\x73\x66\x20\x9f\x52\x69\x63\x68\x72\x66\x20\x9f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```
{% endcode %}

Now we can easily write that to a file:

```
$ python
Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> open("DOS.bin", "wb").write(b'\x0e\x1f\xba\x22\x00\x31(...)')
184
>>> quit()
```

Now we got raw DOS code in that binary! \
DOS code is just 16-bit something something x86.\
According to [https://stackoverflow.com/questions/1737095/how-do-i-disassemble-raw-16-bit-x86-machine-code](https://stackoverflow.com/questions/1737095/how-do-i-disassemble-raw-16-bit-x86-machine-code), we can disassemble it with `objdump` (I added `intel` since I prefer Intel syntax over AT\&T):

```
$ objdump -D -b binary -mi386 -Maddr16,data16,intel DOS.bin 

DOS.bin:     Dateiformat binary


Disassembly of section .data:

00000000 <.data>:
   0:	0e                   	push   cs
   1:	1f                   	pop    ds
   2:	ba 22 00             	mov    dx,0x22
   5:	31 db                	xor    bx,bx
   7:	83 fb 2b             	cmp    bx,0x2b
   a:	74 0d                	je     0x19
   c:	8a 87 22 00          	mov    al,BYTE PTR [bx+0x22]
  10:	34 f7                	xor    al,0xf7
  12:	88 87 22 00          	mov    BYTE PTR [bx+0x22],al
  16:	43                   	inc    bx
  17:	eb ee                	jmp    0x7
  19:	b4 09                	mov    ah,0x9
  1b:	cd 21                	int    0x21
  1d:	b8 01 4c             	mov    ax,0x4c01
  20:	cd 21                	int    0x21
  22:	95                   	xchg   bp,ax
  23:	85 98 99 94          	test   WORD PTR [bx+si-0x6b67],bx
  27:	98                   	cbw    
  28:	8c 83 9f c6          	mov    WORD PTR [bp+di-0x3961],es
  2c:	84 a8 87 85          	test   BYTE PTR [bx+si-0x7a79],ch
  30:	c7                   	(bad)  
  31:	90                   	nop
  32:	85 c3                	test   bx,ax
  34:	9a a8 94 c3 99       	call   0x99c3:0x94a8
  39:	a8 95                	test   al,0x95
  3b:	c4 a8 85 82          	les    bp,DWORD PTR [bx+si-0x7d7b]
  3f:	99                   	cwd    
  40:	a8 c6                	test   al,0xc6
  42:	99                   	cwd    
  43:	a8 b3                	test   al,0xb3
  45:	c7                   	(bad)  
  46:	a4                   	movs   BYTE PTR es:[di],BYTE PTR ds:[si]
  47:	a8 9a                	test   al,0x9a
  49:	c7                   	(bad)  
  4a:	93                   	xchg   bx,ax
  4b:	c4 8a 0d 0d          	les    cx,DWORD PTR [bp+si+0xd0d]
  4f:	0a 24                	or     ah,BYTE PTR [si]
  51:	0d 23 9e             	or     ax,0x9e23
  54:	78 66                	js     0xbc
  56:	20 9f 66 0d          	and    BYTE PTR [bx+0xd66],bl
  5a:	25 9e fc             	and    ax,0xfc9e
  5d:	66 20 9f 66 0d       	data32 and BYTE PTR [bx+0xd66],bl
  62:	24 9e                	and    al,0x9e
  64:	60                   	pusha  
  65:	66 20 9f 66 0d       	data32 and BYTE PTR [bx+0xd66],bl
  6a:	21 9e 71 66          	and    WORD PTR [bp+0x6671],bx
  6e:	20 9f 72 66          	and    BYTE PTR [bx+0x6672],bl
  72:	21 9f 22 66          	and    WORD PTR [bx+0x6622],bx
  76:	20 9f 20 13          	and    BYTE PTR [bx+0x1320],bl
  7a:	25 9e 57             	and    ax,0x579e
  7d:	66 20 9f 20 13       	data32 and BYTE PTR [bx+0x1320],bl
  82:	24 9e                	and    al,0x9e
  84:	63 66 20             	arpl   WORD PTR [bp+0x20],sp
  87:	9f                   	lahf   
  88:	20 13                	and    BYTE PTR [bp+di],dl
  8a:	23 9e 63 66          	and    bx,WORD PTR [bp+0x6663]
  8e:	20 9f b1 13          	and    BYTE PTR [bx+0x13b1],bl
  92:	24 9e                	and    al,0x9e
  94:	73 66                	jae    0xfc
  96:	20 9f b1 13          	and    BYTE PTR [bx+0x13b1],bl
  9a:	22 9e 73 66          	and    bl,BYTE PTR [bp+0x6673]
  9e:	20 9f 52 69          	and    BYTE PTR [bx+0x6952],bl
  a2:	63 68 72             	arpl   WORD PTR [bx+si+0x72],bp
  a5:	66 20 9f 00 00       	data32 and BYTE PTR [bx+0x0],bl
	...
```

Nice! Now that we have the actual code, we can reverse it:\
The first two instructions move `cs` into `ds` by pushing and popping `CS` (probably there is no direct `MOV` instruction for these segment thingies)\
We won't go into x86 segments here, but if I am correct this basically causes the same address space to be used for data then is used for code (meaning fetching code from address `0x12` would yield the same bytes as accessing "data" at address `0x12`. This may seem like this should always be the case, but segments allow different address spaces for code, data, and stack. I think in "modern" x86 code, they are not really used though for that though.).\
Basically, this allows accessing parts of the "code" as data.\
Don't worry if this doesn't make sense, this is just legacy x86 stuff that has to happen.\
\
Then, `0x22` is loaded into the `dx` register.\
This is actually the address of the "encrypted" string (If you look at the disassembly, there is sensible code followed by garbage. This garbage starts at `0x22` and is not actually code, but an encrypted string. Objdump just decoded it as code since that was what we told it to do.).\
( And yes, `0x22` is an address.\
&#x20; Addresses are 16-bit (2 byte), but since the address start with the first instruction at `0`, `0x0022` is a fine address. )

After loading the address, there is a loop with the counter in `bx` that jumps to address `0x19` after `0x2b` (=43) iterations.\
This loop presumably decrypts the flag.\
The amount of loop iterations (43) also match the flag length, so this makes sense.\
At 0x19 when the loop is done, there is two syscalls (`int 0x21`).\
The first one printing a string (`ah = 0x09`), the second one exiting the program (`ah = 0x4c`).\
\
So there is a loop with `bx` holding the current offset in the encrypted string and `dx` holding the string base address that is executed once for each offset presumably decrypting the string.\
But how does it do that?

It just xor's each byte of the encrypted string with `0xf7` (`xor al, 0xf7`).

### Solving it manually (the hard way)

Now that we know what the code does, we can confirm that we are correct and manually solve the challenge (code of `solve.py`):

<pre class="language-python"><code class="lang-python"><strong>raw_code = open("DOS.bin", "rb").read()
</strong>
# encrypted string starts at offset 0x22 and has length 0x2b
encrypted_string = raw_code[0x22 : 0x22 + 0x2b]

# just xor each byte with 0xf7
for b in encrypted_string:
    print(bytes([b ^ 0xf7]).decode(), end = "")

# print a terminating newline
print("")
</code></pre>

Let's try:

```
$ python3 solve.py 
bronco{th1s_pr0gr4m_c4n_b3_run_1n_D0S_m0d3}
```
