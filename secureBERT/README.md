# Fine-tuning SecureBERT on DNRTI dataset
## Goal
This repository adapts SecureBERT on DNRTI dataset. **You need to modify the dataset's path in utils.py to run the project.**

## Usage
**Setup**
```bash
pip install -r requirements.txt
```

**Run**

Fine-tune
```bash
python main.py -m train -o train_test1
```

Inference
```bash
python main.py -m inference -w model_weight_path
```



