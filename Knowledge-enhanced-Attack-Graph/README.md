# IIS-Summer Intern

## Usage
**Setup**

python 3.8
```bash
pip install -r requirements
```

Spacy model's weight can be found at [here](https://drive.google.com/drive/folders/1zVGPpN-i-BLlpFqQERscFGb45PkhfkUm)

**Run**

Generating Technique Templates
```bash
python daniel.py -M techniqueTemplate -O Template/Technique_level --edgeType parsing --techGenLevel technique
```

Generating Attack Graph
```bash
python daniel.py -M attackGraph -O ./output -R "Dataset/Evaluation/Frankenstein Campaign.txt" --edgeType parsing
```

Identidying Mitre Att&ck Techniques (**Technique Template must be generated first**)
```bash
# -T and --techGenLevel has dependency
# Make sure them are matched (i.e. technique templates at -T are generated in --techGenLevel level), or there will be error
python daniel.py -M techniqueIdentify -O ./output -R "Dataset/Evaluation/Frankenstein Campaign.txt" -T Template/Technique_level --edgeType parsing --techGenLevel technique
```

## Directory sturcture
Generate Technique Template at following corresponding directory (**recommended, not required**)
```bash
.
.
├─technique_knowledge_graph
├─Template
│   ├─Technique_level     # --techGenLevel technique
│   ├─SubTechnique_level  # --techGenLevel sub_technique
│   └─Procedure_level     
│      ├─1                # --techGenLevel procedure1
│      └─2                # --techGenLevel procedure2
├─utilities
.
.
```
## Citation

```bibtex
@inproceedings{li2022attackg,
  title        = {AttacKG: Constructing technique knowledge graph from cyber threat intelligence reports},
  author       = {Li, Zhenyuan and Zeng, Jun and Chen, Yan and Liang, Zhenkai},
  booktitle    = {European Symposium on Research in Computer Security},
  pages        = {589--609},
  year         = {2022},
  organization = {Springer}
}
```

```bibtex
@misc{
    title      = {Knowledge-enhanced-Attack-Graph},
    author     = {LI Zhenyuan, Sean S. Chen},
    url        = {https://github.com/li-zhenyuan/Knowledge-enhanced-Attack-Graph},
    year       = {2022}
}
```


