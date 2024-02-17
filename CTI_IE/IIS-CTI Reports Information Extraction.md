# IIS-CTI IE
## Usage
**Setup**

python 3.8
```bash    
pip install -r requirements.txt
```

**Run**

Generate attack graph of each procedure example
```bash!
srl_model = load_predictor('structured-prediction-srl-bert')
crf_model = FCoref()
output_dir = "template/GPT"

tt(srl_model, crf_model, output_dir)
```
Generate attack graph of an CTI report
```bash!
input_text = "Benign activity ran for most of the morning while the tools were being setup for the day.  The activity was modified so the hosts would open Firefox and browse to http://215.237.119.171/config.html. The simulated host then entered URL for BITS Micro APT as http://68.149.51.179/ctfhost2.exe. We used the exploited Firefox backdoor to initiate download of ctfhost2.exe via the Background Intelligent Transfer Service (BITS).  Our server indicated the file was successfully downloaded using the BITS protocol, and soon after Micro APT was executed on the target and connected out to 113.165.213.253:80 for C2.  The attacker tried to elevate using a few different drivers, but it failed once again due to the computer having been restarted without disabling driver signature enforcement.  BBN tried using BCDedit to permanently disable driver signing, but it did not seem to work during the engagement as the drivers failed to work unless driver signing was explicitly disabled during boot."
srl_model = load_predictor('structured-prediction-srl-bert')
crf_model = FCoref()
output_path = "test_report"

attackGraph_generating(input_text, srl_model, crf_model, output_path)

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
    title  = {Knowledge-enhanced-Attack-Graph},
    author = {LI Zhenyuan, Sean S. Chen},
    url    = {https://github.com/li-zhenyuan/Knowledge-enhanced-Attack-Graph},
    year   = {2022}

```

```bibtext
@inproceedings{Otmazgin2022FcorefFA,
  title     = {F-coref: Fast, Accurate and Easy to Use Coreference Resolution},
  author    = {Shon Otmazgin and Arie Cattan and Yoav Goldberg},
  booktitle = {AACL},
  year      = {2022}
}
```