from __future__ import annotations
import math
from typing import Set, List, Dict
import networkx as nx
import graphviz

import Levenshtein
import nltk
from matplotlib import figure
import matplotlib.pyplot as plt
from nltk import Tree
from config import *

import numpy as np

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

    def __init__(self, entity_span:  str, entity_type: int, entity_index: int):
        self.id = entity_index  # entity could include multiple words, we only record the entity root token's position (word num) as unique id
        self.type = ner_labels[entity_type]
        self.nlp = {entity_span}

    def __str__(self):
        return f"{self.type}: {self.nlp}"

    def is_similar_with(self, node: AttackGraphNode) -> bool:
        if self.get_similarity(node) >= 0.4:
            return True
        else:
            return False

    # Modified to limit similarity between 0 and 1
    def get_similarity(self, node: AttackGraphNode) -> float:
        similarity = 0.0
        if self.type == node.type:
            similarity += 0.4
        similarity += 0.6 * get_stringSet_similarity(self.nlp, node.nlp)
        return similarity

    def merge_node(self, node: AttackGraphNode):
        self.nlp |= node.nlp

        node.nlp = self.nlp


class AttackGraph:
    attackgraph_gv: graphviz.Digraph                   # Final Graph
    attackNode_dict: Dict[int, AttackGraphNode]  # coref nodes should point to the same attackGraphNode

    gpt_out: List[List[str, int]]                      # GPT extracted entities and its corresponding location

    related_sentences: List[str]
    techniques: Dict[str, list]  # technique name -> [node_list]

    def __init__(self, input_text, gpt_out, srl_model, crf_model):
        self.attackgraph_gv = graphviz.Digraph()
        self.attackNode_dict = {}

        self.related_sentences = []
        self.techniques = {}

        # Daniel added
        self.num_ents = 7

        self.srl = srl_model
        self.coref = crf_model
        self.gpt_out = gpt_out
        self.input_text = input_text
        self.ent_coref = {}

        # initialize self.entity_coref
        for i in range(self.num_ents):
            for e_i in gpt_out[i]:
                self.ent_coref[e_i[0]] = []

        self.generate()

    def draw(self, image_path):
        self.attackgraph_gv.format = "png"
        self.attackgraph_gv.render(filename=image_path, engine="sfdp")

    def to_json(self, output_path):
        self.attackgraph_gv.format = "json"
        self.attackgraph_gv.render(filename=output_path)

    def generate(self):
        """ Generate Attack Graph based on input text.
        :return: None
        """
        # logging.info("---attack graph generation: Parsing NLP doc to get Attack Graph!---")

        self.parse_entity()
        self.parse_coreference()
        self.SemanticRoleLabeling()

        # logging.info("---attack graph generation: Simplify the Attack Graph!---")

        # self.simplify()
        # self.node_merge()

    def parse_entity(self):
        # logging.info("---attack graph generation: Parsing NLP doc to get Attack Graph nodes!---")

        # Loop for 7 entity typee
        for i in range(self.num_ents):
            for e_i in self.gpt_out[i]:
                attack_node = AttackGraphNode(e_i[0], i, e_i[1])
                self.attackNode_dict[e_i[1]] = attack_node

    def parse_coreference(self):
        pred = self.coref.predict(texts=[self.input_text])

        for coref_set_span in pred[0].get_clusters(as_strings=False):
            for i in range(self.num_ents):
                for e_i in self.gpt_out[i]:
                    match = np.zeros(len(coref_set_span), dtype=bool)
                    m = False
                    e_len = len(e_i[0])
                    for j in range(len(coref_set_span)):
                        for e_span in e_i[1:]:
                            if e_span >= coref_set_span[j][0] and e_span + e_len <= coref_set_span[j][1]:
                                match[j] = True
                                m = True

                    if m:
                        for j in range(len(coref_set_span)):
                            if not match[j]:
                                self.ent_coref[e_i[0]].append(coref_set_span[j])

    @staticmethod
    def words_2_span(words: List[str], sentence: str):
        span = []
        remain_text = sentence
        offset = 0

        for i in range(len(words)):
            start = remain_text.index(words[i])
            end = start + len(words[i])
            span.append((start + offset, end + offset))
            offset += end
            remain_text = remain_text[end:]

        return span

    # Daniel added
    def SemanticRoleLabeling(self):
        """ Perform Semantic Rolelabeing on input text

        :return: None
        """

        # Add all nodes
        for attackNode in self.attackNode_dict.values():
            self.attackgraph_gv.node(name=str(attackNode.id), label=str(attackNode))

        tokenize_text = nltk.sent_tokenize(self.input_text)
        offset = 0
        remain_text = self.input_text

        for i in range(len(tokenize_text)):
            sentence = tokenize_text[i]
            pred = self.srl.predict(sentence)

            for relation in pred['verbs']:
                # if both arg0(Subject) and arg1(Object) exist in current relation
                if 'ARG0:' in relation['description'] and 'V:' in relation['description'] and 'ARG1:' in relation['description']:
                    words_span = self.words_2_span(pred['words'], sentence)
                    tags = relation['tags']
                    V = relation['verb']

                    tags_len = len(tags)
                    k = 0
                    while k < tags_len:
                        if 'ARG0' in tags[k]:
                            start = words_span[k][0]
                            while k < tags_len and 'ARG0' in tags[k]:
                                k += 1
                            end = words_span[k - 1][1]
                            arg0_span = [start, end]
                        elif 'ARG1' in tags[k]:
                            start = words_span[k][0]
                            while k < tags_len and 'ARG1' in tags[k]:
                                k += 1
                            end = words_span[k - 1][1]
                            arg1_span = [start, end]
                        else:
                            k += 1

                    subject = []
                    object = []

                    for e_type in range(self.num_ents):
                        for e_i in self.gpt_out[e_type]:
                            e_len = len(e_i[0])

                            # subject
                            # entity itself
                            for start_idx in e_i[1:]:
                                if max(start_idx - offset, arg0_span[0]) < min(start_idx + e_len - offset, arg0_span[1]):
                                    subject.append(e_i[1])
                                    break
                            # coreference
                            if e_i[1] not in subject:
                                for coref_span in self.ent_coref[e_i[0]]:
                                    if max(coref_span[0] - offset, arg0_span[0]) < min(coref_span[1] - offset, arg0_span[1]):
                                        subject.append(e_i[1])
                                        break

                            # Entity shouldn't be subject and object at the same time
                            if e_i[1] in subject:
                                continue

                            # object
                            # entity itself
                            for start_idx in e_i[1:]:
                                if max(start_idx - offset, arg1_span[0]) < min(start_idx + e_len - offset, arg1_span[1]):
                                    object.append(e_i[1])
                                    break
                            # coreference
                            if e_i[1] not in object:
                                for coref_span in self.ent_coref[e_i[0]]:
                                    if max(coref_span[0] - offset, arg1_span[0]) < min(coref_span[1] - offset, arg1_span[1]):
                                        object.append(e_i[1])
                                        break

                    # Adding edges, connect subject and object with edge(relation = verb)
                    for sub in subject:
                        for obj in object:
                            self.attackgraph_gv.edge(str(sub), str(obj), label=V)

            # Intialize for next iteration
            if i != len(tokenize_text) - 1:
                next_sentence = tokenize_text[i + 1]
                idx = remain_text.index(next_sentence)
                offset += idx
                remain_text = remain_text[idx:]

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

        neighbor_list = self.attackgraph_gv.neighbors(source_node)
        for neighor in neighbor_list:
            self.simplify_foreach_subgraph(neighor)  # recursion

            # check whether to merge the node or not
            if self.attackNode_dict[source_node].is_similar_with(self.attackNode_dict[neighor]) \
                    and self.attackgraph_gv.in_degree(neighor) == 1:
                self.attackgraph_gv = nx.contracted_nodes(self.attackgraph_gv, source_node, neighor, self_loops=False)
                self.attackNode_dict[source_node].merge_node(self.attackNode_dict[neighor])
                self.attackNode_dict.pop(neighor)

    def locate_all_source_node(self) -> List:
        self.source_node_list = []

        for node in self.attackgraph_gv.nodes():
            if self.attackgraph_gv.in_degree(node) == 0:
                self.source_node_list.append(node)

        return self.source_node_list

    def node_merge(self):
        self.original_attackgraph_nx = nx.DiGraph(self.attackgraph_gv)

        merge_graph = nx.Graph()
        node_list = list(self.attackgraph_gv.nodes())

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
                self.attackgraph_gv = nx.contracted_nodes(self.attackgraph_gv, a, b, self_loops=False)
                self.attackNode_dict[a].merge_node(self.attackNode_dict[b])
                self.attackNode_dict.pop(b)

        # logging.info(f"---attack graph generation: There are {self.attackgraph_nx.number_of_nodes()} nodes after node merge!---")
