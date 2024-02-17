ner_labels = ["actor", "executable", "file", "network", "registry", "vulnerability", "system"]

# Techniques that have at least 58 procudeure examples
target_ttp_list = ['T1583', 'T1588', 'T1566', 'T1059', 'T1106', 'T1053', 'T1569', 'T1204', 'T1047', 'T1547', 'T1543', 'T1546', 'T1574', 'T1548', 'T1055', 'T1140', 'T1564', 'T1562', 'T1070', 'T1036', 'T1112', 'T1027', 'T1553', 'T1218', 'T1497', 'T1555', 'T1056', 'T1003', 'T1552', 'T1087', 'T1083', 'T1069', 'T1057', 'T1012', 'T1018', 'T1518', 'T1082', 'T1049', 'T1033', 'T1007', 'T1124', 'T1021', 'T1560', 'T1005', 'T1074', 'T1113', 'T1071', 'T1132', 'T1573', 'T1105', 'T1095', 'T1090', 'T1102', 'T1041']

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