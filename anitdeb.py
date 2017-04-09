# antidebug script

import r2pipe
import logging

LOG_FILENAME = "spideypot.log"
NAME_BIN = "f0"

def main():
	logging.basicConfig(filename=LOG_FILENAME,level=logging.DEBUG)
	logging.debug("[+] Starting SpideyPot")
	bin = init()
	debug(bin)


def init():
	bin = r2pipe.open(NAME_BIN)
	bin.cmd("aaa")
	bin.cmd("doo")
	return bin

def debug():
	logging.debug("[+] Analizing step...")
	step = bin.cmd("ds")
	fun = bin.cmd("afn")
	eip = bin.cmd("dr~eip")
	logging.debug("[X] eip "+eip+" fun "+fun+" step "+step)




if __name__ == "__init__":
	main()
