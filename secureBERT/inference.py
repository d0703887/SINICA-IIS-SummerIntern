from transformers import pipeline
from utils import DNRTI, id2label, label2id
import torch
import transformers
from torch import nn
import evaluate
from tqdm import tqdm
import argparse


def infer(weight_path: str):
    model = transformers.RobertaForTokenClassification.from_pretrained(weight_path, id2label=id2label, label2id=label2id)
    tokenizer = transformers.RobertaTokenizerFast.from_pretrained("ehsanaghaei/SecureBERT_Plus", add_prefix_space=True)
    test_data = DNRTI("test", tokenizer, "inference")
    seqeval = evaluate.load("seqeval")
    preds = []
    lab = []
    with torch.no_grad():
        for data in tqdm(test_data):
            data["labels"] = torch.tensor(data["labels"])
            logits = model(**data).logits
            prediction = logits.argmax(-1)[0].tolist()
            label = data["labels"].tolist()
            preds.append([id2label[p] for (p, l) in zip(prediction, label) if l != -100])
            lab.append([id2label[l] for (p, l) in zip(prediction, label) if l != -100])
    result = seqeval.compute(predictions=preds, references=lab)
    empty = ""
    pre = "precision"
    re = "recall"
    f1 = "f1"
    print(f"{empty:10} {pre:10} {re:7} {f1:3}")
    for k, v in result.items():
        if type(v) == dict:
            print(f"{k:10} {round(v['precision'], 3):<10} {round(v['recall'], 3):<7} {round(v['f1'], 3):<3}")
