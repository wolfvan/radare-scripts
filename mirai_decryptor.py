#!/usr/python

import r2pipe
import sys

global MIRAI_FILE
MIRAI_FILE = ""


def load_arg():
	MIRAI_FILE = sys.argv[1]
	print MIRAI_FILE

def open_bin():
	f = r2pipe.open(MIRAI_FILE)
	f.cmd("aaa")
	#f.cmd("doo")
	f.cmd("oo+")
	return f

def obtainKey(f):
	addr = f.cmd("/c xor byte [eax + edi]")
	key = addr.split("x")[4]
	return str(key)



def main(f):
	a = f.cmd("iS~rodata")
	vaddr = a.split(" ")[1]
	nvaddr = vaddr.split("=")[1]
	f.cmd("s "+nvaddr)

	f.cmd("s +252")
	f.cmd("b 400")
	#offset de 250
	key = obtainKey(f)
	f.cmd("wox "+key) #22 es la clave
	c = f.cmd("px 300")
	print (f.cmd("ps 400"))


if __name__ == "__main__":
	load_arg()
	f = open_bin()
	#extract_add_auth_entry(f)
	main(f)
