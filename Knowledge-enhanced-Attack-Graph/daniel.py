from mitre_ttps.mitreGraphReader import MitreGraphReader
from preprocess.report_preprocess import preprocess_file
from report_parser.ioc_protection import IoCIdentifier
from report_parser.report_parser import IoCNer
from technique_knowledge_graph.attack_graph import AttackGraph
from technique_knowledge_graph.daniel_technique_identifier import TechniqueIdentifier, AttackMatcher
from technique_knowledge_graph.technique_template import TechniqueTemplate

from typing import List, Tuple
import os
import warnings
import json
import sys
import argparse

from spacy.tokens import Doc
from allennlp_models.pretrained import load_predictor
from tqdm import tqdm


def ioc_protection(text: str) -> IoCIdentifier:
    iid = IoCIdentifier(text)
    iid.ioc_protect()
    # iid.check_replace_result()

    return iid


def report_parsing(text: str) -> Tuple[IoCIdentifier, Doc]:
    """

    :param text: input text
    :return:     Bang
    """
    iid = ioc_protection(text)
    text_without_ioc = iid.replaced_text
    ner_model = IoCNer("./new_cti.model")
    doc = ner_model.parse(text_without_ioc)

    return iid, doc


def attackGraph_generating(text: str, output: str = None, edge_type='parsing', srl=None) -> AttackGraph:
    """ Generate Attack Graph.

    :param text:        input text
    :param output:      output filename
    :param edge_type:   'parsing' = Dependency Parsing, 'srl' = Semantic Role Labeling
    :param srl:         Semantic role labeling model, None if in edge_type='parsing'
    :return:            Attack Graph
    """
    text = text.lower()
    iid, doc = report_parsing(text)

    ag = AttackGraph(doc, ioc_identifier=iid, edge_type=edge_type, srl_model=srl)

    if output is not None:
        ag.draw(output)
        ag.to_json_file(output + "_artifacts.json")

    return ag


def techniqueTemplate_generating(output_path: str = None, technique_list: List[str] = None, level: str = 'technique', edge_type='parsing', log_path: str = None) -> None:
    """ Generate Technique Template Database.

    :param output_path:     output directory
    :param technique_list:  list of techniques you want to generate
    :param level:           'technique', 'sub_technique', 'procedure1', 'procedure2'
    :param edge_type:       'parsing' = Dependency Parsing, 'srl' = Semantic Role Labeling
    :param log_path:        log file's path
    :return:                None
    """
    # AllenNLP pre-trained srl-bert
    if edge_type == 'srl':
        srl = load_predictor('structured-prediction-srl-bert')
    else:
        srl = None

    mgr = MitreGraphReader(gml_location="utilities/Tactic_Technique_Reference_Example_latest.gml")
    super_sub_dict = mgr.get_super_sub_technique_dict()
    for super_technique, sub_technique_list in super_sub_dict.items():
        if technique_list is not None and super_technique[12:18] not in technique_list:
            continue

        # technique level
        if level == 'technique':
            sample_list = []
            for sub_technique in sub_technique_list:
                sample_list += mgr.find_examples_for_technique(sub_technique)
            if len(sample_list) != 0:
                techniqueTemplate_generating_perTech(super_technique[12:18], sample_list, output_path, edge_type=edge_type, srl=srl, log_path=log_path)

        # sub technique level
        elif level == 'sub_technique':
            if len(sub_technique_list) == 1:
                sample_list = mgr.find_examples_for_technique(sub_technique_list[0])
                if len(sample_list) != 0:
                    techniqueTemplate_generating_perTech(super_technique[12:18], sample_list, output_path, edge_type=edge_type, srl=srl, log_path=log_path)
            else:
                cur = 1
                for sub_technique in sub_technique_list:
                    sample_list = mgr.find_examples_for_technique(sub_technique)
                    if len(sample_list) != 0:
                        techniqueTemplate_generating_perTech(f'{super_technique[12:18]}_{cur:03}', sample_list,
                                                             output_path, edge_type=edge_type, srl=srl, log_path=log_path)
                    cur += 1

        # procedure1 level
        elif level == 'procedure1':
            if len(sub_technique_list) == 1:
                sample_list = mgr.find_examples_for_technique(sub_technique_list[0])
                if len(sample_list) != 0:
                    if not os.path.exists(os.path.join(output_path, super_technique[12:18])):
                        techniqueTemplate_generating_perExample(super_technique[12:18], sample_list,
                                                                os.path.join(output_path, super_technique[12:18]), edge_type=edge_type, srl=srl, log_path=log_path)
            else:
                for sub_technique in sub_technique_list:
                    sample_list = mgr.find_examples_for_technique(sub_technique)
                    if len(sample_list) != 0:
                        if not os.path.exists(os.path.join(output_path, sub_technique[12:21].replace("/", "_"))):
                            techniqueTemplate_generating_perExample(f'{sub_technique[12:21].replace("/", "_")}', sample_list,
                                                                    os.path.join(output_path, sub_technique[12:21].replace("/", "_")), edge_type=edge_type, srl=srl, log_path=log_path)

        # procedure2 level
        elif level == 'procedure2':
            if len(sub_technique_list) == 1:
                if not os.path.exists(f"{output_path}/{super_technique[12:18]}"):
                    os.mkdir(f"{output_path}/{super_technique[12:18]}")

                sample_list = mgr.find_examples_for_technique(sub_technique_list[0])
                for i in range(len(sample_list)):
                    techniqueTemplate_generating_perTech(f'{super_technique[12:18]}_{i + 1}', [sample_list[i]],
                                                         os.path.join(output_path, super_technique[12:18]), edge_type=edge_type, srl=srl, log_path=log_path)
            else:
                cur = 1
                for sub_technique in sub_technique_list:
                    if not os.path.exists(f'{output_path}/{super_technique[12:18]}_{cur:03}'):
                        os.mkdir(f'{output_path}/{super_technique[12:18]}_{cur:03}')

                    sample_list = mgr.find_examples_for_technique(sub_technique)
                    for i in range(len(sample_list)):
                        techniqueTemplate_generating_perTech(f'{super_technique[12:18]}_{cur:03}_{i + 1}',
                                                             [sample_list[i]],
                                                             os.path.join(output_path, f"{super_technique[12:18]}_{cur:03}"), edge_type=edge_type, srl=srl, log_path=log_path)
                    cur += 1


def techniqueTemplate_generating_perTech(technique_name: str, technique_samples: List[str], output_path: str = None, edge_type='parsing', srl=None, log_path: str = None) -> None:
    """ Combine all procedure examples in technique_samples into single Technique Template.

    :param technique_name:      technique's name
    :param technique_samples:   list of procedure examples
    :param output_path:         output directory
    :param edge_type:           'parsing' = Dependency parsing, 'srl' = Semantic Role Labeling
    :param srl:                 Semantic role labeling model, None if in edge_type='parsing'
    :param log_path:            log file's path
    :return:                    None
    """
    technique_template = TechniqueTemplate(technique_name)

    total_count = len(technique_samples)
    pbar = tqdm(technique_samples, position=0)
    for sample in pbar:
        pbar.set_description(technique_name)

        sample_graph = attackGraph_generating(sample, edge_type=edge_type, srl=srl)
        technique_template.update_template(sample_graph)

    if log_path is not None:
        with open(log_path, "a") as fp:
            fp.write(f"Update {technique_name} with {total_count} examples\n")

    if output_path is not None:
        technique_template.dump_to_file(f"{output_path}/{technique_name}")


def techniqueTemplate_generating_perExample(technique_name: str, technique_samples: List[str], output_path: str = None, edge_type='parsing', srl=None, log_path: str = None) -> None:
    """ Combine similar examples in technique_samples into same Technique Template.

    :param technique_name:      technique's name
    :param technique_samples:   list of procedure examples
    :param output_path:         output directory
    :param edge_type:           'parsing' = Dependency parsing, 'srl' = Semantic Role Labeling
    :param srl:                 Semantic role labeling model, None if in edge_type='parsing'
    :param log_path:            log file's path
    :return: None
    """
    if not os.path.exists(output_path):
        os.mkdir(output_path)
    length = len(technique_samples)
    identifier_list = []

    # Generate first Technique Template
    idx = 0
    while idx < length:
        technique_template = TechniqueTemplate(technique_name)
        sample = technique_samples[idx]
        technique_template.update_template(attackGraph_generating(sample, edge_type=edge_type, srl=srl))
        idx += 1
        if len(technique_template.technique_node_list) >= 3:
            identifier_list.append(TechniqueIdentifier(technique_template))
            break

    pbar = tqdm(range(idx, length), position=0)
    for i in pbar:
        pbar.set_description(technique_name)

        sample = technique_samples[i]
        sample_graph = attackGraph_generating(sample, edge_type=edge_type, srl=srl)

        for identifier in identifier_list:
            identifier.graph_alignment(sample_graph)

        max_score = 0
        max_index = 0
        index = 0
        for identifier in identifier_list:
            if identifier.get_graph_alignment_score() > max_score:
                max_score = identifier.get_graph_alignment_score()
                max_index = index
            index += 1

        if max_score < 0.7:
            tmp = TechniqueTemplate(technique_name)
            tmp.update_template(sample_graph)
            tmp_identifier = TechniqueIdentifier(tmp)
            if len(tmp_identifier.technique_template.technique_node_list) >= 3:
                identifier_list.append(tmp_identifier)
        else:
            identifier_list[max_index].technique_template.update_template(sample_graph)

    print(f"{technique_name}: #samples={length}, #templates={len(identifier_list)}")
    if log_path is not None:
        with open(log_path, "a") as fp:
            fp.write(f"{technique_name}: #samples={length}, #templates={len(identifier_list)}\n")

    length = len(identifier_list)
    if output_path is not None and length != 0:
        for i in range(length):
            identifier_list[i].technique_template.dump_to_file(f"{output_path}/{technique_name}_{i}")
    else:
        os.rmdir(output_path)


def technique_identifying(text: str, technique_list: List[str], template_path: str, output_file: str = "output", edge_type='parsing', level='technique') -> AttackMatcher:
    """ Identify the possible technique in input text, considering only the techniques in input technique_list.

    :param text:            text waiting for identification
    :param technique_list:  list of techniques you want to used
    :param template_path:   template's path
    :param output_file:     output filename
    :param edge_type:       'parsing' = Dependency Parsing, 'srl' = Semantic Role Labeling
    :param level:           'technique', 'sub_technique', 'procedure1', 'procedure2'
    :return:                AttackMatcher
    """
    if edge_type == 'srl':
        srl = load_predictor('structured-prediction-srl-bert')
    else:
        srl = None

    ag = attackGraph_generating(text, edge_type=edge_type, srl=srl)
    tt_list = load_techniqueTemplate_fromFils(template_path, technique_list, level)

    attackMatcher = technique_identifying_forAttackGraph(ag, tt_list, output_file)

    return attackMatcher


def technique_identifying_forAttackGraph(graph: AttackGraph, template_list: List[TechniqueTemplate], output_file: str) -> AttackMatcher:
    """

    :param graph:           attack graph waiting for identification
    :param template_list:   list of technique template
    :param output_file:     output filename
    :return:                AttackMatcher
    """
    attackMatcher = AttackMatcher(graph)
    for template in template_list:
        attackMatcher.add_technique_identifier(TechniqueIdentifier(template))
    attackMatcher.attack_matching()
    attackMatcher.to_json_file(output_file + "_techniques.json")

    return attackMatcher


def load_techniqueTemplate_fromFils(technique_path, tt_list, level='technique'):
    """ Load Technique Template from template_path, considering only techniques in tt_list.

    :param technique_path:  path of Technique Templates to be loaded
    :param tt_list:         list of techniques you want to load
    :param level:           'technique', 'sub_technique', 'procedure1', 'procedure2'
    :return:                loaded Technique Template list
    """
    template_list = []

    if level == 'technique' or level == 'sub_technique':
        for template_file in os.listdir(technique_path):
            tech_name, ext = template_file.split('.')
            if tech_name in tt_list and ext == "json":
                template = TechniqueTemplate(tech_name)
                template.load_from_file(os.path.join(technique_path, template_file))
                template_list.append(template)
    elif level == 'procedure1' or level == 'procedure2':
        for technique in os.listdir(technique_path):
            if technique in tt_list:
                for template_file in os.listdir(os.path.join(technique_path, technique)):
                    if template_file.endswith(".json"):
                        template = TechniqueTemplate(template_file.replace(".json", ""))
                        template.load_from_file(os.path.join(technique_path, technique, template_file))
                        template_list.append(template)

    return template_list


def TechIdentifyJson(filepath) -> List[str]:
    """ Print out formatted technique identification result.

    :param filepath: input technique_identification result json file
    :return:         a list of techniques appeared in input file
    """
    with open(filepath, 'r') as fp:
        j = json.load(fp)

    neigh = []
    techs = {}
    convert = {}
    ans = []

    for technique, attri in j.items():
        ans.append(technique)
        head = list(j[technique].keys())[0]
        if head not in neigh:
            neigh.append(head)
            convert[head] = list(j[technique].keys())
            techs[head] = [technique]
        else:
            techs[head].append(technique)

    for key, value in techs.items():
        print(f"{convert[key]}: ", end='')
        for te in value:
            print(f'"{te}"', end=', ')
        print()

    return ans


def drawTechniqueTemplate(template_path) -> None:
    """ Draw all Technique Templates in template_path.

    :param template_path: path of Techniqute Templates
    :return:              None
    """
    for template in os.listdir(template_path):
        if template.endswith(".json") and not os.path.exists(os.path.join(template_path, template.replace(".json", ".png"))):
            tmp = TechniqueTemplate('tmp')
            tmp.load_from_file(os.path.join(template_path, template))
            tmp.pretty_print(os.path.join(template_path, template.replace(".json", ".png")), level='complete')


if __name__ == '__main__':
    warnings.filterwarnings("ignore")
    # frequently appeared techniques
    tt_list = ['T1595_001', 'T1595_002', 'T1595_003', 'T1592_001', 'T1592_002', 'T1592_003', 'T1592_004', 'T1589_001',
               'T1589_002', 'T1589_003', 'T1590_001', 'T1590_002', 'T1590_003', 'T1590_004', 'T1590_005', 'T1590_006',
               'T1591_001', 'T1591_002', 'T1591_003', 'T1591_004', 'T1598_001', 'T1598_002', 'T1598_003', 'T1597_001',
               'T1597_002', 'T1596_001', 'T1596_002', 'T1596_003', 'T1596_004', 'T1596_005', 'T1593_001', 'T1593_002',
               'T1593_003', 'T1203', 'T1559_001', 'T1559_002', 'T1559_003', 'T1106', 'T1053_002', 'T1053_003',
               'T1053_005', 'T1053_006', 'T1053_007', 'T1047', 'T1098_001', 'T1098_002', 'T1098_003', 'T1098_004',
               'T1098_005', 'T1140', 'T1112', 'T1601_001', 'T1601_002', 'T1599_001', 'T1027_001', 'T1027_002',
               'T1027_003', 'T1027_004', 'T1027_005', 'T1027_006', 'T1027_007', 'T1027_008', 'T1027_009', 'T1027_010',
               'T1027_011', 'T1083', 'T1046', 'T1135', 'T1120', 'T1069_001', 'T1069_002', 'T1069_003', 'T1057', 'T1012',
               'T1018', 'T1518_001', 'T1082', 'T1614_001', 'T1016_001', 'T1049', 'T1033', 'T1007', 'T1124', 'T1119',
               'T1005', 'T1113', 'T1008', 'T1105', 'T1095', 'T1041', 'T1011_001', 'T1052_001', 'T1567_001', 'T1567_002',
               'T1567_003', 'T1486', 'T1565_001', 'T1565_002', 'T1565_003', 'T1491_001', 'T1491_002', 'T1561_001',
               'T1561_002', 'T1499_001', 'T1499_002', 'T1499_003', 'T1499_004']

    parser = argparse.ArgumentParser()

    # Examples:
    # python daniel.py -M attackGraph -O ./output -R Dataset/Evaluation/Frankenstein Campaign.txt --edgeType parsing
    # python daniel.py -M techniqueTemplate -O Template/Technique_level --edgeType parsing --techGenLevel technique
    # python daniel.py -M techniqueIdentify -O ./output -R Dataset/Evaluation/Frankenstein Campaign.txt -T Template/Technique_level --edgeType parsing --techGenLevel technique
    parser.add_argument('-M', '--mode', required=True, type=str, default="", help="The running mode options: 'attackGraph', 'techniqueTemplate', 'techniqueIdentify'")
    parser.add_argument('-O', '--outputPath', required=True, type=str, default="", help="Output file's path.")
    parser.add_argument('-L', '--logPath', required=False, type=str, default=None, help="Log file's path.")
    parser.add_argument('-R', '--reportPath', required=False, type=str, default="Dataset/Evaluation/Frankenstein Campaign.txt", help="Target report's path.")
    parser.add_argument('-T', '--templatePath', required=False, type=str, default="", help="Technique template's path.")

    # daniel added
    parser.add_argument('--edgeType', required=True, type=str, default="pasring", help="Ways to select edges: 'pasring', 'srl'.")
    parser.add_argument('--techGenLevel', required=False, type=str, default="technique", help="Generate Techinque Template based on given level: 'technique', 'sub_technique', 'procedure1', 'procedure2'.")

    arguments = parser.parse_args(sys.argv[1:])

    report_path = arguments.reportPath
    report_text = preprocess_file(report_path)

    running_mode = arguments.mode
    if running_mode == 'attackGraph':
        if arguments.edgeType == 'srl':
            srl = load_predictor('structured-prediction-srl-bert')
        else:
            srl = None
        ag = attackGraph_generating(text=report_text, output=arguments.outputPath, edge_type=arguments.edgeType, srl=srl)
    elif running_mode == 'techniqueTemplate':
        techniqueTemplate_generating(output_path=arguments.outputPath, technique_list=tt_list, level=arguments.techGenLevel, edge_type=arguments.edgeType, log_path=arguments.logPath)
    elif running_mode == 'techniqueIdentify':
        technique_identifying(text=report_text, technique_list=tt_list, template_path=arguments.templatePath, output_file=arguments.outputPath, edge_type=arguments.edgeType, level=arguments.techGenLevel)
    else:
        print("Unknown running mode!")

    print("Done")





