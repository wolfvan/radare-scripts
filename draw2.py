import networkx as nx
import matplotlib.pyplot as plt

def import_log():
	lista = []
	f = open("recolecc.log", "r")
	count = 0
	for line in f:
		if (count +1)%2 != 0:
			print line
			lista.append(line[:-1])
		count = count +1

	print lista
	return lista

def uno(lista):
	dic={}
	for i in range(1,len(lista)):
		dic[i]=lista[i]
	return dic

def draw(dic):
	G = nx.path_graph(len(dic))
	H = nx.relabel_nodes(G, dic)
	nx.draw(H)
	plt.savefig("mydic.png")
	plt.show()


if __name__ == "__main__":
	lista = import_log()
	dic_ = uno(lista)
	draw(dic_)
