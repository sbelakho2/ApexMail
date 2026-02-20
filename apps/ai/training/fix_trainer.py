#!/usr/bin/env python3
"""Fix train_r14.py for TRL 0.28.0 API compatibility."""

with open("/workspace/train/train_r14.py", "r") as f:
    code = f.read()

# 1. Replace import: TrainingArguments -> SFTConfig, add SFTConfig import
code = code.replace("from trl import SFTTrainer, SFTConfig", "from trl import SFTTrainer, SFTConfig")
code = code.replace("from trl import SFTTrainer", "from trl import SFTTrainer, SFTConfig")

# 2. Remove TrainingArguments import line
code = code.replace("    TrainingArguments,\n", "")

# 3. Replace TrainingArguments( with SFTConfig(
code = code.replace("training_args = TrainingArguments(", "training_args = SFTConfig(")

# 4. Add max_length, packing, dataset_text_field to SFTConfig
# Insert before closing paren of training_args
code = code.replace(
    "    ddp_find_unused_parameters=False,\n)",
    "    ddp_find_unused_parameters=False,\n    max_length=4096,\n    packing=True,\n    dataset_text_field=\"text\",\n)"
)

# 5. Remove max_length, dataset_text_field, packing from SFTTrainer constructor
# They may appear in any order, handle each individually
for line in [
    "    max_length=4096,\n",
    "    dataset_text_field=\"text\",\n",
    "    packing=True,\n",
]:
    # Only remove from the SFTTrainer section (not from SFTConfig)
    # Find the SFTTrainer block and remove these lines from it
    pass

# More targeted: find the SFTTrainer block and clean it
import re
trainer_match = re.search(r'(trainer = SFTTrainer\(.*?\))', code, re.DOTALL)
if trainer_match:
    trainer_block = trainer_match.group(1)
    clean_block = trainer_block
    clean_block = clean_block.replace("    max_length=4096,\n", "")
    clean_block = clean_block.replace("    dataset_text_field=\"text\",\n", "")
    clean_block = clean_block.replace("    packing=True,\n", "")
    code = code.replace(trainer_block, clean_block)

with open("/workspace/train/train_r14.py", "w") as f:
    f.write(code)

print("Fixed train_r14.py for TRL 0.28.0!")
