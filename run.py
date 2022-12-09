#!/usr/bin/python
from __future__ import annotations
from heapq import heapify, heapreplace
from typing import List, Tuple, Dict
from pwn import *
import struct
from pwnlib.tubes.remote import remote
from pwnlib.tubes.process import process
from pwnlib.util.packing import u8, u16, u32, u64, p8, p16, p32, p64
from os import system
from funcy import chunks # list(chunks(4, b"AAAABBBB")) // [b'AAAA', b'BBBB']

terminalSetting = ["tmux", "new-window"]
context.clear(terminal=terminalSetting, arch="amd64", bits=64, os="linux")

def nasm(code: str) -> bytes:
    with tempfile.NamedTemporaryFile(mode = "w") as f_in:
        f_in.write(code)
        f_in.flush()
        with tempfile.NamedTemporaryFile() as f_out:
            cmd = " ".join(["nasm", "-o", f_out.name, f_in.name])
            os.system(cmd)
            return f_out.read()

with open("./bios.bin", "wb") as bios_out:
    with open("task1.S", "r") as asm_in:
        source = asm_in.read()
    out = nasm(source)
    bios_out.write(p8(0x0)*0x30000) #pad to bios start offset
    bios_out.write(out)
    bios_out.flush()

cmd = "qemu-system-i386 -bios ./bios.bin -net none -cpu base -monitor none -no-reboot -nographic -serial stdio -s"
print(cmd)
cmd = cmd.split(" ")

gdbscript = """
target remote localhost:1234
set $main = 0xf1164
# continue
""".strip()

gdbscriptf = None
if not args["GDB"]:
    if args["ATTACH"]:
        cmd = cmd + ["-S"]
    io: process = process(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE)
if args["ATTACH"]:
    gdbscriptf = tempfile.NamedTemporaryFile(suffix = '.gdb')
    gdbscriptf.write(gdbscript.encode())
    gdbscriptf.flush()
    gdbcmd = f'gdb -ix "./gdb_init_real_mode.txt" -ex "set tdesc filename ./target.xml" -x {gdbscriptf.name}'
    run_in_new_terminal(gdbcmd, preexec_fn = None)

io.send(b"aaaa\n\x00")

io.interactive()
io.close()
if gdbscriptf is not None:
    gdbscriptf.close()
