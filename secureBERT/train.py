import os
os.environ["CUDA_VISIBLE_DEVICES"] = "2, 3"
import torch
from torch import nn
import transformers
from utils import DNRTI, compute_metrics, id2label, label2id
from transformers import TrainingArguments, Trainer
import argparse

def train(output_dir:str):
    model = transformers.RobertaForTokenClassification.from_pretrained("ehsanaghaei/SecureBERT", id2label=id2label, label2id=label2id)
    model.classifier = nn.Linear(in_features=768, out_features=27, bias=True)

    # for param in model.roberta.parameters():
    #     param.requires_grad = False

    tokenizer = transformers.RobertaTokenizerFast.from_pretrained("ehsanaghaei/SecureBERT", add_prefix_space=True)
    train_data = DNRTI("train", tokenizer, "train")
    test_data = DNRTI("test", tokenizer, "train")

    data_collator = transformers.DataCollatorForTokenClassification(tokenizer=tokenizer)

    training_args = TrainingArguments(
        output_dir=output_dir,
        learning_rate=0.00005,
        per_device_train_batch_size=4,
        per_device_eval_batch_size=4,
        num_train_epochs=60,
        weight_decay=0,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        push_to_hub=False,
        report_to=["tensorboard"]
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_data,
        eval_dataset=test_data,
        tokenizer=tokenizer,
        data_collator=data_collator,
        compute_metrics=compute_metrics,
    )
    trainer.train()










