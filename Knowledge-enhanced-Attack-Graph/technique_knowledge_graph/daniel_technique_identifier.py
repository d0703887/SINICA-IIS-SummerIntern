from technique_knowledge_graph.technique_template import *

import itertools

import xlsxwriter
import sys
sys.path.extend([".", "technique_knowledge_graph"])


class NodeMatchInstance:
    matched_node: AttackGraphNode
    matched_score: float

    def __init__(self, node, score):
        self.matched_node = node
        self.matched_score = score


# Record TechniqueTemplate Matching Record
class TechniqueIdentifier:
    technique_template: TechniqueTemplate

    node_match_record: dict
    edge_match_record: dict
    node_count: int
    edge_count: int

    def __init__(self, technique_template: TechniqueTemplate):
        self.technique_template = technique_template
        logging.info(f"---technique identification: Init technique template {technique_template.technique_name} as identifier!---")

        self.node_match_record = {}
        self.node_count = len(self.technique_template.technique_node_list)
        self.edge_match_record = {}
        self.edge_count = len(self.technique_template.technique_edge_dict.keys())

    def node_alignment(self, attack_node: AttackGraphNode):
        """ Determine tecnnique template's nodes that are similar to attack_node.

        :param attack_node: attack node
        :return: None
        """
        index = -1
        for technique_node in self.technique_template.technique_node_list:
            index += 1

            # complete template node list
            if technique_node.instance_count == 0:
                self.node_match_record[index] = None
                continue

            # accept node as a match
            node_similarity_score = technique_node.get_similarity(attack_node)
            if node_similarity_score >= TechniqueTemplate.NODE_SIMILAR_ACCEPT_THRESHOLD:
                if index not in self.node_match_record.keys():
                    self.node_match_record[index] = []
                self.node_match_record[index].append((attack_node, node_similarity_score))

    def graph_alignment(self, attack_graph: AttackGraph):
        """ Compute similarity between techniqute tempplate and whole attack_graph.

        :param attack_graph: input attack graph
        :return: None
        """
        self.node_match_record = {}
        for node in attack_graph.attackNode_dict.values():
            self.node_alignment(node)

        k_list = []
        v_list = []
        for k, v in self.node_match_record.items():
            k_list.append(k)
            if v is None:
                v_list.append([''])
            else:
                v_list.append(v)

        self.node_match_record = {}
        best_match_score = 0
        best_match_record = {}
        for item in itertools.product(*v_list):
            for i in range(0, len(k_list)):
                if item[i] == '':
                    self.node_match_record[k_list[i]] = None
                else:
                    self.node_match_record[k_list[i]] = item[i]

            for template_edge, instance_count in self.technique_template.technique_edge_dict.items():
                source_index = template_edge[0]
                sink_index = template_edge[1]

                # No matched node for edge
                try:
                    if self.node_match_record[source_index] is None or self.node_match_record[sink_index] is None:
                        self.edge_match_record[template_edge] = 0.0
                        continue
                except:
                    self.edge_match_record[template_edge] = 0.0
                    continue

                # source & sink node is in atack graph
                source_node = self.node_match_record[source_index][0]
                sink_node = self.node_match_record[sink_index][0]

                if source_node == sink_node:
                    distance = 1
                else:
                    try:
                        distance = nx.shortest_path_length(attack_graph.attackgraph_nx, source_node.id, sink_node.id)
                    except (nx.NodeNotFound, nx.NetworkXNoPath, ValueError) as ex:
                        self.edge_match_record[template_edge] = 0.0
                        continue

                source_node_matching_score = self.node_match_record[source_index][1]
                sink_node_matching_score = self.node_match_record[sink_index][1]

                edge_matching_score = math.sqrt(source_node_matching_score * sink_node_matching_score) / distance
                self.edge_match_record[template_edge] = edge_matching_score

            match_score = self.get_graph_alignment_score()
            if match_score > best_match_score:
                best_match_score = match_score
                best_match_record = self.node_match_record

        self.node_match_record = best_match_record

    def subgraph_alignment(self, subgraph: set, attack_graph: AttackGraph):
        """ Compute similarity between technique template and the subgraph of the attack_graph.

        :param subgraph: subgraph of attack_graph
        :param attack_graph: input attack graph
        :return: None
        """
        self.node_match_record = {}
        for node in subgraph:
            self.node_alignment(attack_graph.attackNode_dict[node])

        k_list = []
        v_list = []
        for k, v in self.node_match_record.items():
            k_list.append(k)
            if v is None:
                v_list.append([''])
            else:
                v_list.append(v)

        self.node_match_record = {}
        best_match_score = 0
        best_match_record = {}
        for item in itertools.product(*v_list):
            for i in range(0, len(k_list)):
                if item[i] == '':
                    self.node_match_record[k_list[i]] = None
                else:
                    self.node_match_record[k_list[i]] = item[i]

            for template_edge, instance_count in self.technique_template.technique_edge_dict.items():
                source_index = template_edge[0]
                sink_index = template_edge[1]

                # No matched node for edge
                try:
                    if self.node_match_record[source_index] is None or self.node_match_record[sink_index] is None:
                        self.edge_match_record[template_edge] = 0.0
                        continue
                except:
                    self.edge_match_record[template_edge] = 0.0
                    continue

                # source & sink node is in atack graph
                source_node = self.node_match_record[source_index][0]
                sink_node = self.node_match_record[sink_index][0]

                if source_node == sink_node:
                    distance = 1
                else:
                    try:
                        distance = nx.shortest_path_length(attack_graph.attackgraph_nx, source_node.id, sink_node.id)
                    except:
                        self.edge_match_record[template_edge] = 0.0
                        continue

                source_node_matching_score = self.node_match_record[source_index][1]
                sink_node_matching_score = self.node_match_record[sink_index][1]

                edge_matching_score = math.sqrt(source_node_matching_score * sink_node_matching_score) / distance
                self.edge_match_record[template_edge] = edge_matching_score

            match_score = self.get_graph_alignment_score()
            if match_score > best_match_score:
                best_match_score = match_score
                best_match_record = self.node_match_record

        self.node_match_record = best_match_record

    def get_graph_alignment_score(self):
        return (self.get_node_alignment_score() + self.get_edge_alignment_score()) / 2

    def get_node_alignment_score(self):
        """ Compute the final node alignment score, details please refer to AttacKG.

        :return: node alignment score
        """
        node_alignment_score = 0.0

        if self.node_match_record is None:
            return 0
        index = 0
        total_instance_count = 0
        for node_index, node_node_similarity in self.node_match_record.items():
            if self.technique_template.technique_node_list[node_index].type == "actor":
                continue

            if node_node_similarity is not None:
                # ToDo: Need to select the larger similarity score
                node_alignment_score += node_node_similarity[1] * self.technique_template.technique_node_list[node_index].instance_count  # math.sqrt
                total_instance_count += self.technique_template.technique_node_list[node_index].instance_count

            index += 1

        if node_alignment_score == 0:
            return 0
        else:
            return node_alignment_score / total_instance_count

    def get_edge_alignment_score(self):
        """ Compute final edge alignment score, details please refer to AttacKG.

        :return: edge alignment score
        """
        edge_alignment_score = 0.0
        total_instance_count = 0
        for edge, edge_similarity in self.edge_match_record.items():
            edge_alignment_score += edge_similarity * (self.technique_template.technique_edge_dict[edge])
            total_instance_count += self.technique_template.technique_edge_dict[edge]

        if edge_alignment_score == 0:
            return 0
        else:
            return edge_alignment_score / total_instance_count


# Matching process, involve multiple TechniqueIdentifier at one time
class AttackMatcher:
    attack_graph: AttackGraph
    attack_graph_nx: nx.DiGraph
    technique_identifier_list: list
    technique_matching_score: dict
    technique_matching_subgraph: dict
    technique_matching_record: dict

    normalized_factor: float

    def __init__(self, attack_graph: AttackGraph):
        self.attack_graph = attack_graph
        self.attack_graph_nx = attack_graph.attackgraph_nx
        self.technique_identifier_list = []
        self.technique_matching_score = {}
        self.technique_matching_subgraph = {}
        self.technique_matching_record = {}

        self.normalized_factor = self.attack_graph_nx.number_of_nodes() + self.attack_graph_nx.number_of_edges()

    def add_technique_identifier(self, technique_identifier: TechniqueIdentifier):
        """ Add technique_identifier into technique_identifier_list.

        :param technique_identifier: Technique Identifier waited to be added
        :return: None
        """
        if technique_identifier.edge_count == 0:
            return

        self.technique_identifier_list.append(technique_identifier)

    def attack_matching(self):
        """ Perform graph matching between Technique Idnetifier in technique_identifier_list and attack_graph.

        :return: None
        """
        # subgraph_list = nx.strongly_connected_components(self.attack_graph_nx)
        subgraph_list = nx.connected_components(self.attack_graph_nx.to_undirected())

        count = 0
        for subgraph in subgraph_list:
            count += 1

            for technique_identifier in self.technique_identifier_list:
                technique_identifier.subgraph_alignment(subgraph, self.attack_graph)

            # find the most match technique
            for technique_identifier in self.technique_identifier_list:
                node_alignment_score = technique_identifier.get_graph_alignment_score()

                if technique_identifier.technique_template.technique_name not in self.technique_matching_score.keys():
                    self.technique_matching_score[technique_identifier.technique_template.technique_name] = node_alignment_score
                    self.technique_matching_subgraph[technique_identifier.technique_template.technique_name] = subgraph
                    self.technique_matching_record[technique_identifier.technique_template.technique_name] = technique_identifier.node_match_record
                elif self.technique_matching_score[technique_identifier.technique_template.technique_name] < node_alignment_score:
                    self.technique_matching_score[technique_identifier.technique_template.technique_name] = node_alignment_score
                    self.technique_matching_subgraph[technique_identifier.technique_template.technique_name] = subgraph
                    self.technique_matching_record[technique_identifier.technique_template.technique_name] = technique_identifier.node_match_record

                # logging.debug("---S3.2: matching result %s\n=====\n%s - %f!---" % (technique_identifier.technique_template.technique_name, subgraph, node_alignment_score))

    def print_match_result(self) -> dict:
        logging.info(str(self.technique_matching_score))
        logging.info(str(self.technique_matching_subgraph))
        logging.info(str(self.technique_matching_record))

        return self.technique_matching_score

    def to_json(self) -> dict:
        """ Convert matching result into json format.

        :return json_string
        """
        selected_techniques_dict = {}

        for k, v in self.technique_matching_score.items():
            if v >= 0.5:
                # selected_techniques_dict[k] = tuple(self.technique_matching_subgraph[k])
                involved_node_dict = {}
                for node in self.technique_matching_subgraph[k]:
                    if self.attack_graph.attackNode_dict[node].ioc != set():
                        involved_node_dict[node] = {
                            "type": self.attack_graph.attackNode_dict[node].type,
                            "nlp": tuple(self.attack_graph.attackNode_dict[node].nlp),
                            "ioc": tuple(self.attack_graph.attackNode_dict[node].ioc)}
                if involved_node_dict != {}:
                    selected_techniques_dict[k] = involved_node_dict

        json_string = json.dumps(selected_techniques_dict)
        return json_string

    def to_json_file(self, output_file):
        """ Dump matching result into json file.

        :param output_file: output file path
        :return: None
        """
        with open(output_file, "w+") as output:
            output.write(self.to_json())


# haven't been used
class Evaluation:

    def __init__(self):
        self.book = xlsxwriter.Workbook("technique_matching_result.xlsx")
        self.sheet = self.book.add_worksheet('report_pickTechnique')
        self.column_count = 1

        self.match_format = self.book.add_format({'bg_color': '#FFC7CE', 'font_color': '#9C0006'})

    def add_technique_list(self, technique_list: list):
        row_count = 1
        for technique in technique_list:
            self.sheet.write(0, row_count, technique)
            row_count += 1

    def add_result(self, report_name: str, detection_result: dict, ground_truth: list):
        self.sheet.write(self.column_count, 0, report_name)

        row_count = 1
        for technique, result in detection_result.items():
            self.sheet.write(self.column_count, row_count, result)
            technique_name = technique.replace("'", "").replace("_", "/")
            if technique_name in ground_truth:
                self.sheet.conditional_format(self.column_count, row_count, self.column_count, row_count, {'type': '2_color_scale'})
            row_count += 1

        self.column_count += 1
