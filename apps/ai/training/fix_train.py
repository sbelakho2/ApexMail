#!/usr/bin/env python3
"""Fix train.py for TRL 0.27.x API compatibility."""

with open("train.py", "r") as f:
    content = f.read()

# 1. Move max_seq_length, packing, dataset_text_field from SFTTrainer to TrainingArguments
old_trainer = """    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=dataset["train"],
        eval_dataset=dataset["validation"],
        processing_class=tokenizer,
        max_seq_length=train_cfg["max_seq_length"],
        packing=train_cfg.get("packing", True),
        dataset_text_field="text",
    )"""

new_trainer = """    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=dataset["train"],
        eval_dataset=dataset["validation"],
        processing_class=tokenizer,
    )"""

content = content.replace(old_trainer, new_trainer)

# 2. Add max_seq_length and packing to TrainingArguments
old_args_end = '        run_name=f"apexmail-qwen7b-{ts}",\n    )'

new_args_end = '''        run_name=f"apexmail-qwen7b-{ts}",
        max_seq_length=train_cfg["max_seq_length"],
        packing=train_cfg.get("packing", True),
        dataset_text_field="text",
    )'''

content = content.replace(old_args_end, new_args_end)

with open("train.py", "w") as f:
    f.write(content)

print("Fixed train.py for TRL 0.27.x")
