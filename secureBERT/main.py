from train import train
from inference import infer
import argparse


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", help="train, inference", required=True)
    parser.add_argument("-o", "--output_dir", help="output directory when training", required=False)
    parser.add_argument("-w", "--weight_path", help="model's weight path when inferencing", required=False)
    arg = parser.parse_args()

    if arg.mode == "train":
        if arg.output_dir is not None:
           train(arg.output_dir)
        else:
            print("Provide training output directory!")
    elif arg.mode == "inference":
        if arg.weight_path is not None:
            infer(arg.weight_path)
        else:
            print("Provide model's weight path!")
    else:
        print("Unknown mode.")

