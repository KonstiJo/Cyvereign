"""
training/scripts/train_lora.py
==============================
LoRA Fine-Tuning Pipeline for Cyvereign.

This script fine-tunes a HuggingFace causal language model with LoRA adapters
using the PEFT library.  It is designed to work with instruction-tuning datasets
in JSONL format (see training/datasets/README.md for the expected format).

Why LoRA?
---------
Full fine-tuning of a 7B parameter model requires ~56 GB VRAM.  LoRA adds a
small number of trainable adapter matrices while keeping the base model frozen.
With 4-bit quantisation (QLoRA) this fits in ~8 GB VRAM – perfect for the
RTX 5070 (12 GB).

Requirements:
  pip install torch transformers peft datasets accelerate bitsandbytes

Usage:
  python training/scripts/train_lora.py \
    --base_model "deepseek-ai/deepseek-coder-6.7b-instruct" \
    --dataset    "training/datasets/cybersec_instruct.jsonl" \
    --output_dir "training/output/lora_adapter"
"""

import argparse
import json
from pathlib import Path

import torch
from datasets import Dataset
from peft import LoraConfig, TaskType, get_peft_model, prepare_model_for_kbit_training
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    DataCollatorForSeq2Seq,
    Trainer,
    TrainingArguments,
)


# ---------------------------------------------------------------------------
# Default hyperparameters – tune these for your hardware and dataset
# ---------------------------------------------------------------------------
DEFAULTS = {
    "base_model": "deepseek-ai/deepseek-coder-6.7b-instruct",
    "dataset": "training/datasets/cybersec_instruct.jsonl",
    "output_dir": "training/output/lora_adapter",
    # LoRA configuration
    "lora_r": 16,          # rank of adapter matrices (higher = more capacity)
    "lora_alpha": 32,      # scaling factor (usually 2 × lora_r)
    "lora_dropout": 0.05,
    # Training configuration
    "epochs": 3,
    "batch_size": 4,
    "grad_accum": 4,       # effective batch size = batch_size × grad_accum
    "lr": 2e-4,
    "max_seq_len": 2048,
    "warmup_ratio": 0.03,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fine-tune a model with LoRA")
    parser.add_argument("--base_model",  default=DEFAULTS["base_model"])
    parser.add_argument("--dataset",     default=DEFAULTS["dataset"])
    parser.add_argument("--output_dir",  default=DEFAULTS["output_dir"])
    parser.add_argument("--lora_r",      type=int,   default=DEFAULTS["lora_r"])
    parser.add_argument("--lora_alpha",  type=int,   default=DEFAULTS["lora_alpha"])
    parser.add_argument("--lora_dropout",type=float, default=DEFAULTS["lora_dropout"])
    parser.add_argument("--epochs",      type=int,   default=DEFAULTS["epochs"])
    parser.add_argument("--batch_size",  type=int,   default=DEFAULTS["batch_size"])
    parser.add_argument("--grad_accum",  type=int,   default=DEFAULTS["grad_accum"])
    parser.add_argument("--lr",          type=float, default=DEFAULTS["lr"])
    parser.add_argument("--max_seq_len", type=int,   default=DEFAULTS["max_seq_len"])
    return parser.parse_args()


def load_jsonl_dataset(path: str) -> Dataset:
    """
    Load a JSONL dataset for instruction fine-tuning.

    Expected JSONL format (one JSON object per line):
        {"instruction": "...", "input": "...", "output": "..."}

    "input" is optional – if absent it is treated as an empty string.
    """
    records = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return Dataset.from_list(records)


def format_prompt(example: dict) -> dict:
    """
    Convert an instruction-tuning record into a single training string.

    The format follows Alpaca-style prompting, which most coding models
    have been pre-trained to understand.
    """
    instruction = example.get("instruction", "")
    inp = example.get("input", "")
    output = example.get("output", "")

    if inp:
        prompt = (
            f"### Instruction:\n{instruction}\n\n"
            f"### Input:\n{inp}\n\n"
            f"### Response:\n{output}"
        )
    else:
        prompt = (
            f"### Instruction:\n{instruction}\n\n"
            f"### Response:\n{output}"
        )
    return {"text": prompt}


def main() -> None:
    args = parse_args()
    output_path = Path(args.output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    print(f"[train_lora] Base model  : {args.base_model}")
    print(f"[train_lora] Dataset     : {args.dataset}")
    print(f"[train_lora] Output dir  : {args.output_dir}")
    print(f"[train_lora] Device      : {'cuda' if torch.cuda.is_available() else 'cpu'}")

    # -----------------------------------------------------------------------
    # 1. Load tokenizer
    # -----------------------------------------------------------------------
    tokenizer = AutoTokenizer.from_pretrained(args.base_model, trust_remote_code=True)
    if tokenizer.pad_token is None:
        # Many causal LMs do not define a pad token; reuse EOS token
        tokenizer.pad_token = tokenizer.eos_token

    # -----------------------------------------------------------------------
    # 2. Load base model with 4-bit quantisation (QLoRA)
    # -----------------------------------------------------------------------
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_use_double_quant=True,   # double quantisation saves extra memory
        bnb_4bit_quant_type="nf4",        # NormalFloat4 – best quality at 4-bit
        bnb_4bit_compute_dtype=torch.bfloat16,
    )

    model = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        quantization_config=bnb_config,
        device_map="auto",                # automatically distribute across GPUs
        trust_remote_code=True,
    )

    # Prepare for k-bit training (freezes base weights, casts layer norms)
    model = prepare_model_for_kbit_training(model)

    # -----------------------------------------------------------------------
    # 3. Attach LoRA adapters
    # -----------------------------------------------------------------------
    lora_config = LoraConfig(
        task_type=TaskType.CAUSAL_LM,
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
        # Apply LoRA to the query and value projection matrices in attention
        target_modules=["q_proj", "v_proj"],
        bias="none",
    )

    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    # -----------------------------------------------------------------------
    # 4. Load and tokenise dataset
    # -----------------------------------------------------------------------
    raw_dataset = load_jsonl_dataset(args.dataset)
    formatted = raw_dataset.map(format_prompt)

    def tokenize(example: dict) -> dict:
        return tokenizer(
            example["text"],
            truncation=True,
            max_length=args.max_seq_len,
            padding=False,
        )

    tokenized = formatted.map(tokenize, remove_columns=formatted.column_names)

    # -----------------------------------------------------------------------
    # 5. Configure and run training
    # -----------------------------------------------------------------------
    training_args = TrainingArguments(
        output_dir=args.output_dir,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        warmup_ratio=DEFAULTS["warmup_ratio"],
        fp16=not torch.cuda.is_bf16_supported(),
        bf16=torch.cuda.is_bf16_supported(),
        logging_steps=10,
        save_steps=100,
        save_total_limit=2,
        report_to="none",               # disable wandb / tensorboard by default
        optim="paged_adamw_32bit",      # memory-efficient optimizer for QLoRA
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized,
        data_collator=DataCollatorForSeq2Seq(tokenizer, pad_to_multiple_of=8),
    )

    print("[train_lora] Starting training …")
    trainer.train()

    # -----------------------------------------------------------------------
    # 6. Save the LoRA adapter (NOT the full model weights)
    # -----------------------------------------------------------------------
    model.save_pretrained(args.output_dir)
    tokenizer.save_pretrained(args.output_dir)
    print(f"[train_lora] LoRA adapter saved to: {args.output_dir}")
    print(
        "[train_lora] To use the adapter, load the base model and apply:\n"
        "  from peft import PeftModel\n"
        f"  model = PeftModel.from_pretrained(base_model, '{args.output_dir}')"
    )


if __name__ == "__main__":
    main()
