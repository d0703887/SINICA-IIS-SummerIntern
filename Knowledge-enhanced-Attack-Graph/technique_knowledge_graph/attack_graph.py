from __future__ import annotations
import math
from typing import Set

import Levenshtein
from matplotlib import figure
import matplotlib.pyplot as plt
from nltk import Tree
import spacy.tokens
from spacy.tokens import Span
# import simplejson as json

from report_parser.report_parser import *
from report_parser.ioc_protection import *
from mitre_ttps.mitreGraphReader import *



def to_nltk_tree(node):
    if node.n_lefts + node.n_rights > 0:
        return Tree(node.orth_, [to_nltk_tree(child) for child in node.children])
    else:
        return node.orth_


def tok_format(tok):
    return "@".join([tok.orth_, tok.tag_, tok.dep_, tok.ent_type_])  # , tok.dep_])


def to_nltk_formatted_tree(node):
    if node.n_lefts + node.n_rights > 0:
        return Tree(tok_format(node), [to_nltk_formatted_tree(child) for child in node.children])
    else:
        return tok_format(node)


# node_shape = "so^>v<dph8"
node_shape_dict = {
    "actor": "o",
    "executable": "o",
    "file": "s",
    "network": "d",
    "registry": "p",
    "vulnerability": "8",
    "system": "^",
}


def get_iocSet_similarity(set_m: Set[str], set_n: Set[str]) -> float:
    return get_stringSet_similarity(set_m, set_n)


def get_nlpSet_similarity(set_m: Set[str], set_n: Set[str]) -> float:
    return get_stringSet_similarity(set_m, set_n)


def get_stringSet_similarity(set_m: Set[str], set_n: Set[str]) -> float:
    max_similarity = 0.0
    for m in set_m:
        for n in set_n:
            similarity = get_string_similarity(m, n)
            max_similarity = max_similarity if max_similarity > similarity else similarity
    return max_similarity


# https://blog.csdn.net/dcrmg/article/details/79228589
def get_string_similarity(a: str, b: str) -> float:
    similarity_score = Levenshtein.ratio(a, b)
    return similarity_score


class AttackGraphNode:
    id: int
    type: str

    ioc: Set[str]
    nlp: Set[str]

    position: int

    def __init__(self, entity: Span):
        self.id = entity.root.i  # entity could include multiple words, we only record the entity root token's position (word num) as unique id
        self.type = entity.root.ent_type_
        self.nlp = {entity.text}
        self.ioc = set()
        self.position = entity.root.idx

    def __str__(self):
        # return f"Node #{self.id}: [type: '{self.type}', nlp: '{self.nlp}', ioc: '{self.ioc}', position: '{self.position}']"

        if self.ioc == set():
            return f"#{self.id}, {self.type}: {self.nlp}, {{}}"
        else:
            return f"#{self.id}, {self.type}: {self.nlp}, {self.ioc}"

    def is_similar_with(self, node: AttackGraphNode) -> bool:
        if self.get_similarity(node) >= 0.4:
            return True
        else:
            return False

    # Modified to limit similarity between 0 and 1
    def get_similarity(self, node: AttackGraphNode) -> float:  # Todo
        similarity = 0.0
        if self.type == node.type:
            similarity += 0.4
        similarity += 0.6 * max(get_stringSet_similarity(self.ioc, node.ioc), get_stringSet_similarity(self.nlp, node.nlp))
        return similarity

    def merge_node(self, node: AttackGraphNode):
        self.nlp |= node.nlp
        self.ioc |= node.ioc

        node.nlp = self.nlp
        node.ioc = self.ioc


class AttackGraph:
    attackgraph_nx: nx.DiGraph                   # Final Graph
    attackNode_dict: Dict[int, AttackGraphNode]  # coref nodes should point to the same attackGraphNode

    nlp_doc: spacy.tokens.doc.Doc                # Output of Spacy model
    ioc_identifier: IoCIdentifier                # Output of IoCProtection (which contains replaced IoC)

    related_sentences: List[str]
    techniques: Dict[str, list]  # technique name -> [node_list]

    def __init__(self, doc, ioc_identifier=None, edge_type='parsing', srl_model=None):
        self.attackgraph_nx = nx.DiGraph()
        self.attackNode_dict = {}

        self.nlp_doc = doc
        self.ioc_identifier = ioc_identifier

        self.related_sentences = []
        self.techniques = {}

        # Daniel added
        self.srl = srl_model

        self.generate(edge_type)

    # http://sparkandshine.net/en/networkx-application-notes-a-better-way-to-visualize-graphs/
    # https://networkx.org/documentation/latest/auto_examples/drawing/plot_chess_masters.html#sphx-glr-auto-examples-drawing-plot-chess-masters-py
    def draw(self, image_path: str = "") -> figure:
        fig_size = math.ceil(math.sqrt(self.attackgraph_nx.number_of_nodes())) * 10
        plt.subplots(figsize=(fig_size, fig_size))  # Todo: re-consider the figure size.

        graph_pos = nx.spring_layout(self.attackgraph_nx, scale=2, iterations=50)
        plt.xlim([-3, 3])
        plt.ylim([-3, 3])

        for label in ner_labels:
            nx.draw_networkx_nodes(self.attackgraph_nx,
                                   graph_pos,
                                   node_shape=node_shape_dict[label],
                                   nodelist=[node for node in filter(lambda n: self.attackNode_dict[n].type == label, self.attackgraph_nx.nodes)],
                                   node_size=500,
                                   alpha=0.6)
        nx.draw_networkx_labels(self.attackgraph_nx,
                                graph_pos,
                                labels={node: str(self.attackNode_dict[node]) for node in self.attackgraph_nx.nodes},
                                verticalalignment='top',
                                horizontalalignment='left',
                                font_size=8)
        nx.draw_networkx_edges(self.attackgraph_nx, graph_pos, arrowsize=20)
        nx.draw_networkx_edge_labels(self.attackgraph_nx,
                                     graph_pos,
                                     edge_labels=nx.get_edge_attributes(self.attackgraph_nx, 'action'),
                                     font_size=8)

        if image_path == "":
            wm = plt.get_current_fig_manager()
            wm.window.state('zoomed')
            plt.show()
        else:
            plt.savefig(image_path)

    def to_json(self):
        node_dict = {}
        for nid, node in self.attackNode_dict.items():
            node_dict[nid] = {}
            node_dict[nid]["type"] = node.type
            node_dict[nid]["nlp"] = tuple(node.nlp)
            node_dict[nid]["ioc"] = tuple(node.ioc)

        json_string = json.dumps(node_dict)
        return json_string

    def to_json_file(self, output_file):
        with open(output_file, "w+") as output:
            output.write(self.to_json())

    def generate(self, edge_type):
        """ Generate Attack Graph based on input text.

        :param edge_type: 'parsing' = Dependency Parsing, 'srl' = Semantic Role Labeling
        :return: None
        """
        # logging.info("---attack graph generation: Parsing NLP doc to get Attack Graph!---")

        self.parse_entity()
        self.parse_coreference()
        if edge_type == 'parsing':
            self.parse_dependency()
        elif edge_type == 'srl':
            self.SemanticRoleLabeling()

        # logging.info("---attack graph generation: Simplify the Attack Graph!---")

        self.simplify()
        self.node_merge()

    def parse_entity(self):
        # logging.info("---attack graph generation: Parsing NLP doc to get Attack Graph nodes!---")

        for entity in self.nlp_doc.ents:
            if entity.root.ent_type_ in ner_labels:  # and re.match("NN.*", entity.root.tag_):  # Todo
                attack_node = AttackGraphNode(entity)
                self.attackNode_dict[entity.root.i] = attack_node

                for token in entity:
                    self.attackNode_dict[token.i] = self.attackNode_dict[entity.root.i]
                    if token.idx in self.ioc_identifier.replaced_ioc_dict.keys():
                        self.attackNode_dict[entity.root.i].ioc.add(self.ioc_identifier.replaced_ioc_dict[token.idx])
            else:
                continue

    def parse_coreference(self):
        # logging.info("---attack graph generation: Parsing NLP doc to get Co-references!---")

        for coref_set in self.nlp_doc._.coref_chains:
            # get ioc-related coreferences sets
            coref_origin = 0
            for coref_item in coref_set:
                if coref_item.root_index in self.attackNode_dict.keys():
                    coref_origin = coref_item.root_index
                    break

            # pasing the coreferences
            if coref_origin != 0:  # if coref_origin == 0, coref is not related to any iocs; otherwise, coref_origin record the position of related ioc
                logging.debug("---coref_origin:---")
                for coref_item in coref_set:
                    self.attackNode_dict[coref_item.root_index] = self.attackNode_dict[coref_origin]

                    coref_token = self.nlp_doc[coref_item.root_index]
                    logging.debug("%s-%s" % (coref_token, coref_token.ent_type_))

    # Daniel added
    def SemanticRoleLabeling(self):
        """ Perform Semantic Rolelabeing on input text

        :return: None
        """

        # Check whether SRL and AttackG partition sentence in the same way
        pred = self.srl.predict(self.nlp_doc.text)
        length = len(pred['verbs'][0]['tags'])
        count = 0
        for _ in self.nlp_doc:
            count += 1
        # If SRL and AttackG partition sentence in different way, can't utilize semantic role labeling (for now, there might be ways to solve this)
        if length != count:
            return

        # Add all nodes
        for i in self.attackNode_dict.values():
            self.attackgraph_nx.add_node(i.id)

        # Parse dependency using Semantic Role Labeling
        offset = 0
        for sentence in self.nlp_doc.sents:
            pred = self.srl.predict(sentence.text)
            length = len(pred['verbs'][0]['tags'])

            # Add edges
            # Preprocssing srl prediction
            for relation in pred['verbs']:

                # Both arg0(Subject) and arg1(Object) exist in current relation
                if 'ARG0:' in relation['description'] and 'V:' in relation['description'] and 'ARG1:' in relation['description']:
                    for j in re.findall(r"[^[]*\[([^]]*)\]", relation['description']):
                        if 'V:' in j:
                            V = j.split(" ")[-1]

                    tags = relation['tags']
                    arg0 = []
                    arg1 = []

                    for ent in self.nlp_doc.ents:
                        if ent.root.i - offset < length:
                            if 'ARG0' in tags[ent.root.i - offset]:
                                arg0.append(ent.root.i)
                            # ARG1, Manner, Location are all viewed as Object
                            elif 'ARG1' in tags[ent.root.i - offset] or 'ARGM-MNR' in tags[ent.root.i - offset] or 'ARGM-LOC' in tags[ent.root.i - offset]:
                                arg1.append(ent.root.i)

                    # Adding edges, connect subjec and object with edge(relation = verb)
                    for a0 in arg0:
                        for a1 in arg1:
                            self.attackgraph_nx.add_edge(a0, a1, action=V)

            offset = length

    def parse_dependency(self):
        """ Dependency parsing on each sentence.

        :return: None
        """
        # logging.info("---attack graph generation: Parsing NLP doc to get Attack Graph Edges!---")
        for sentence in self.nlp_doc.sents:
            self.parse_dependency_perSentence(sentence)

    def parse_dependency_perSentence(self, sentence):
        # logging.info(f"---attack graph generation: Parsing sentence: {sentence}!---")

        node_queue = []
        tvb = ""
        tnode = -1

        root = sentence.root
        is_related_sentence = False

        # traverse the nltk tree
        node_queue.append(root)
        while node_queue:
            node = node_queue.pop(0)
            for child in node.children:
                node_queue.append(child)

            if node.i in self.attackNode_dict.keys():
                is_related_sentence = True
                self.attackgraph_nx.add_node(self.attackNode_dict[node.i].id)

                if tnode != -1:
                    self.attackgraph_nx.add_edge(tnode, node.i, action=tvb)
                tnode = node.i

        if is_related_sentence:
            self.related_sentences.append(sentence.text)
            # logging.debug("Related sentence: %s" % sentence.text)

        return self.attackgraph_nx

    source_node_list: list
    visited_node_list: list

    def simplify(self):
        """ Merge similar node.

        :return: None
        """
        # logging.info(f"---attack graph generation: There are {self.attackgraph_nx.number_of_nodes()} nodes before simplification!---")
        source_node_list = self.locate_all_source_node()
        self.visited_node_list = []

        for source_node in source_node_list:
            self.simplify_foreach_subgraph(source_node)

        # logging.info(f"---attack graph generation: There are {self.attackgraph_nx.number_of_nodes()} nodes after simplification!---")

    def simplify_foreach_subgraph(self, source_node):
        if source_node not in self.visited_node_list:
            self.visited_node_list.append(source_node)
        else:
            return

        neighbor_list = self.attackgraph_nx.neighbors(source_node)
        for neighor in neighbor_list:
            self.simplify_foreach_subgraph(neighor)  # recursion

            # check whether to merge the node or not
            if self.attackNode_dict[source_node].is_similar_with(self.attackNode_dict[neighor]) \
                    and self.attackgraph_nx.in_degree(neighor) == 1:
                self.attackgraph_nx = nx.contracted_nodes(self.attackgraph_nx, source_node, neighor, self_loops=False)
                self.attackNode_dict[source_node].merge_node(self.attackNode_dict[neighor])
                self.attackNode_dict.pop(neighor)

    def locate_all_source_node(self) -> List:
        self.source_node_list = []

        for node in self.attackgraph_nx.nodes():
            if self.attackgraph_nx.in_degree(node) == 0:
                self.source_node_list.append(node)

        return self.source_node_list

    def node_merge(self):
        self.original_attackgraph_nx = nx.DiGraph(self.attackgraph_nx)

        merge_graph = nx.Graph()
        node_list = list(self.attackgraph_nx.nodes())

        for m in range(0, len(node_list)):
            for n in range(m + 1, len(node_list)):
                node_m = self.attackNode_dict[node_list[m]]
                node_n = self.attackNode_dict[node_list[n]]

                if node_m.get_similarity(node_n) / math.log(abs(node_m.id - node_n.id) + 2) >= 0.3 \
                        and ((len(node_m.ioc) == 0 and len(node_n.ioc) == '') or len(node_m.ioc & node_n.ioc) != 0):
                    merge_graph.add_edge(node_list[m], node_list[n])

        for subgraph in nx.connected_components(merge_graph):
            subgraph_list = list(subgraph)
            a = subgraph_list[0]
            for b in subgraph_list[1:]:
                self.attackgraph_nx = nx.contracted_nodes(self.attackgraph_nx, a, b, self_loops=False)
                self.attackNode_dict[a].merge_node(self.attackNode_dict[b])
                self.attackNode_dict.pop(b)

        # logging.info(f"---attack graph generation: There are {self.attackgraph_nx.number_of_nodes()} nodes after node merge!---")
