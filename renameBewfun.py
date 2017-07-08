import r2pipe
import sys
import os


#usage #!pipe python ./renameBewfun.py bew

def rename(binary):
  self.r2.cmd("afn main 0x080480f8")
  self.r2.cmd("afn syscall2_res_connection 0x0805c070")
  self.r2.cmd("afn send_hostname 0x0804a779")
  self.r2.cmd("afn syscall1_fun 0x804bfa4")
  self.r2.cmd("afn ult_ie 0x8060150")
  self.r2.cmd("afn CallGoogle 0x0804A000")
  self.r2.cmd("afn GestionCert 0x0805C070)
  self.r2.cmd("afn NombraLinux 0x0804A779")
  self.r2.cmd("afn NombraLinux 0x0804A779")
  self.r2.cmd("afn Set192 0x0804B315")
  self.r2.cmd("afn SetPath 0x0804A9F4")
  self.r2.cmd("afn ResolveServer 0x0805F90C")
  self.r2.cmd("afn TheScalar2 0x0805C4D0")
  self.r2.cmd("afn UDP_n 0x08048FA4")
  self.r2.cmd("afn someEtcHosts 0x0804B090")
  self.r2.cmd("afn someUserAgent 0x08049824")
  self.r2.cmd("afn setUDP 0x0805D4F0")
  self.r2.cmd("afn tempfilex11Conf 0x0804A36B")
  self.r2.cmd("afn UniqID 0x0804A928")
  


    
def execute(binary):
	r2pipe.open(binary)
	r2.cmd("aaa")
	rename(bianry)



if __name__ == "__main__":
	binary = sys.argv[1]
	initt(binary)

