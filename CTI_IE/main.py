from technique_knowledge_graph.GPT_attack_graph import AttackGraph
from config import *

from typing import List, Tuple
import os
import re

from allennlp_models.pretrained import load_predictor
from tqdm import tqdm
from fastcoref import FCoref
import openai
import networkx as nx


def entity_extraction(text: str) -> List[List[Tuple[str, int]]]:
    """ Utilize GPT to extract entities

    :param text: input text
    :return: extracted entities
    """
    system_prompt = "You are a Named Entity Recognition system. I will provide you entity types, output format and the target paragraph where you extract entities from. You should return the extracted entities following the output format and provide no explanation."

    guideline_prompt = "Entity types:\n" \
                       "1. threat actor\n" \
                       "2. executable\n" \
                       "3. file\n" \
                       "4. network\n" \
                       "5. registry\n" \
                       "6. vulnerability\n" \
                       "7. system\n" \
                       "\n" \
                       "Output format:\n" \
                       "{'threat actor': [list of entities present], 'executable': [list of entities present], 'file': [list of entities present], 'network': [list of entities present], 'registry': [list of entities present], 'vulnerability': [list of entities present], 'system': [list of entities present]}\n" \
                       "\n" \
                       "If no entities are presented in an entity type, mark it as empty list.\n" \
                       "\n" \
                       f"target paragraph: {text}"

    completion = openai.ChatCompletion.create(model="gpt-3.5-turbo-1106",
                                              messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": guideline_prompt}])

    dic = eval(completion.choices[0].message.content)
    gpt_out = [[] for _ in range(7)]

    i = 0
    for item in dic.values():
        if item is not None:
            for ent in item:
                remain_text = text
                e_i = [ent]
                e_len = len(ent)
                offset = 0
                while ent in remain_text:
                    idx = remain_text.index(ent)
                    e_i.append(idx + offset)
                    remain_text = remain_text[idx + e_len:]
                    offset += idx + e_len
                if len(e_i) != 1:
                    gpt_out[i].append(tuple(e_i))
        i += 1

    return gpt_out


def attackGraph_generating(text: str, srl_model, crf_model, output_path) -> AttackGraph:
    """ Generate Attack Graph.

    :param text:        input text
    :param srl_model:   Semantic Role Labeling model
    :param crf_model:   Co-reference model
    :param output_path: path of output file, without extension
    :return:            Attack Graph
    """

    try:
        gpt_out = entity_extraction(text)
    except SyntaxError:
        return

    ag = AttackGraph(text, gpt_out, srl_model, crf_model)

    if output_path is not None:
        ag.draw(output_path)
        ag.to_json(output_path)
        os.remove(output_path)


def tt(srl_model, crf_model, output_dir: str = "template/GPT"):
    """ gnerate attack graph of each procedure example

    :param srl_model:   Semantic Role Labeling model
    :param crf_model:   Co-reference model
    :param output_dir: output directory
    :return:
    """
    mgr = nx.read_gml("utilities/Tactic_Technique_Reference_Example_latest.gml")
    for node in mgr.nodes():
        if mgr.nodes[node]["types"] == "technique":
            if node[12:] in target_ttp_list:
                count = 0
                # Check directory
                if not os.path.exists(os.path.join(output_dir, node[12:])):
                    os.makedirs(os.path.join(output_dir, node[12:]))
                # Procedure examples
                for nei in mgr.neighbors(node):
                    if mgr.nodes[nei]["types"] == "examples":
                        count += 1
                        if not os.path.exists(os.path.join(output_dir, node[12:], f"{node[12:]}_{count}.json")):
                            attackGraph_generating(re.sub("\[[0-9]+\]+", "", nei), srl_model, crf_model, os.path.join(output_dir, node[12:], f"{node[12:]}_{count}"))

        elif mgr.nodes[node]["types"] == "super_technique":
            if node[12:] in target_ttp_list:
                count = 0
                # Check directory
                if not os.path.exists(os.path.join(output_dir, node[12:])):
                    os.makedirs(os.path.join(output_dir, node[12:]))
                # Procedure examples
                for sub_tech in mgr.neighbors(node):
                    if mgr.nodes[sub_tech]["types"] == "sub_technique":
                        for nei in mgr.neighbors(sub_tech):
                            if mgr.nodes[nei]["types"] == "examples":
                                count += 1
                                if not os.path.exists(os.path.join(output_dir, node[12:], f"{node[12:]}_{count}.json")):
                                    attackGraph_generating(re.sub("\[[0-9]+\]+", "", nei), srl_model, crf_model, os.path.join(output_dir, node[12:], f"{node[12:]}_{count}"))


if __name__ == '__main__':

    # enter your openai api key
    openai.api_key = ""
    srl_model = load_predictor('structured-prediction-srl-bert')
    crf_model = FCoref()
    tt(srl_model, crf_model)

