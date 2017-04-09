#trace_graph


#import matplotlib
#import nx.Graph()

DIC = {}
DEBUG = True
FUN_LIST= []


def open_file():
	f = open("tracegraph1.log", "r")
	return f

def append_list(f):
	FUN_LIST=[]
	for line in f:
		if DEBUG:
			if "Analizing" not in line:
				fun_name = line.split(":")[2][:-1]
				FUN_LIST.append(fun_name)
	return FUN_LIST

def count_fun(lista):
	count = 1
	lista2 = []
	j = 0
	for i in range(0, len(lista)):
		try:
			if lista[i] == lista[i+1]:
				count = count +1
			else:
				print lista[i]
				print count
				count = 1
		except:
			pass
			#	count = count +1
			#else:
			#	print count
			#	DIC[lista[i]] = count
			#	count = 1
		#except:
		#	pass


def main():
	f = open_file()
	lista = append_list(f)
	count_fun(lista)




if __name__ == "__main__":
	main()
