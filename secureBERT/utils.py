import numpy as np
import evaluate


id2label = {0: 'O',
            1: 'B-Area',
            2: 'I-Area',
            3: 'B-Exp',
            4: 'I-Exp',
            5: 'B-Features',
            6: 'I-Features',
            7: 'B-HackOrg',
            8: 'I-HackOrg',
            9: 'B-Idus',
            10: 'I-Idus',
            11: 'B-OffAct',
            12: 'I-OffAct',
            13: 'B-Org',
            14: 'I-Org',
            15: 'B-Purp',
            16: 'I-Purp',
            17: 'B-SamFile',
            18: 'I-SamFile',
            19: 'B-SecTeam',
            20: 'I-SecTeam',
            21: 'B-Time',
            22: 'I-Time',
            23: 'B-Tool',
            24: 'I-Tool',
            25: 'B-Way',
            26: 'I-Way'}

label2id = {'O': 0,
            'B-Area': 1,
            'I-Area': 2,
            'B-Exp': 3,
            'I-Exp': 4,
            'B-Features': 5,
            'I-Features': 6,
            'B-HackOrg': 7,
            'I-HackOrg': 8,
            'B-Idus': 9,
            'I-Idus': 10,
            'B-OffAct': 11,
            'I-OffAct': 12,
            'B-Org': 13,
            'I-Org': 14,
            'B-Purp': 15,
            'I-Purp': 16,
            'B-SamFile': 17,
            'I-SamFile': 18,
            'B-SecTeam': 19,
            'I-SecTeam': 20,
            'B-Time': 21,
            'I-Time': 22,
            'B-Tool': 23,
            'I-Tool': 24,
            'B-Way': 25,
            'I-Way': 26}


def tokenize_and_align_labels(sample, tokenizer, mode="train"):
    tokenized_inputs = tokenizer(sample["tokens"], truncation=True, is_split_into_words=True, return_tensors=(None if mode == "train" else "pt"))

    word_ids = tokenized_inputs.word_ids(batch_index=0)
    previous_word_idx = None
    label_ids = []
    for word_idx in word_ids:
        if word_idx is None:
            label_ids.append(-100)
        elif word_idx != previous_word_idx:
            label_ids.append(label2id[sample["ner_tags"][word_idx]])
        else:
            label_ids.append(-100)

    tokenized_inputs["labels"] = label_ids
    return tokenized_inputs


def DNRTI(file_type, tokenizer, mode="train"):
    if file_type == "train":
        path = "../dataset/DNRTI/train.txt"
    elif file_type == "test":
        path = "../dataset/DNRTI/test.txt"
    elif file_type == "val":
        path = "../dataset/DNRTI/valid.txt"

    with open(path, "r", encoding='utf-8') as fp:
        data = str(fp.read()).split("\n\n")

    ans = []
    cnt = 0
    for sent in data:
        cur = {"id": cnt, "tokens": [], "ner_tags": []}
        cnt += 1
        sent = sent.split("\n")
        for word in sent:
            if " " in word:
                word, label = word.rsplit(" ", 1)
                word = word.strip(" ")
                if label != "":
                    cur["tokens"].append(word)
                    cur["ner_tags"].append(label)
        ans.append(tokenize_and_align_labels(cur, tokenizer, mode))

    return ans


def compute_metrics(p):
    prediction, labels = p
    predictions = np.argmax(prediction, axis=2)

    true_predictions = [[id2label[p] for (p, l) in zip(prediction, label) if l != -100] for prediction, label in zip(predictions, labels)]
    true_labels = [[id2label[l] for (p, l) in zip(prediction, label) if l != -100] for prediction, label in zip(predictions, labels)]

    seqeval = evaluate.load("seqeval")
    results = seqeval.compute(predictions=true_predictions, references=true_labels)
    return {
        "precision": results["overall_precision"],
        "recall": results["overall_recall"],
        "f1": results["overall_f1"],
        "accuracy": results["overall_accuracy"]
    }