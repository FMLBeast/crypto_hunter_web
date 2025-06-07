import networkx as nx
import matplotlib.pyplot as plt

# load
G = nx.read_graphml('derivation.graphml')

# pick a subgraph (e.g. first 200 nodes) to keep it legible
nodes = list(G.nodes())[:200]
H = G.subgraph(nodes)

# layout & draw
pos = nx.spring_layout(H)
nx.draw_networkx_nodes(H, pos, node_size=[int(H.nodes[n]['size'] or 100) for n in H])
nx.draw_networkx_edges(H, pos, alpha=0.3)
nx.draw_networkx_labels(H, pos, labels={n: H.nodes[n]['label'] for n in H}, font_size=6)
plt.axis('off')
plt.show()
