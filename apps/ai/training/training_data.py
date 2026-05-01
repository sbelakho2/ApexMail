from __future__ import annotations

import json
from pathlib import Path


def _prompt_catalog_path(data_file: str | Path) -> Path | None:
    path = Path(data_file)
    candidates = [path.parent / "system_prompts.json"]
    if path.is_absolute() and len(path.parts) > 2:
        candidates.append(Path("/workspace/data/system_prompts.json"))
    candidates.append(Path(__file__).resolve().parents[3] / "data" / "system_prompts.json")

    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _load_prompts(data_file: str | Path) -> dict[str, str]:
    catalog_path = _prompt_catalog_path(data_file)
    if catalog_path is None:
        raise FileNotFoundError(
            f"system_prompt_id records require system_prompts.json next to {data_file}"
        )

    catalog = json.loads(catalog_path.read_text())
    prompts = catalog.get("prompts", catalog)
    return {
        prompt_id: value["content"] if isinstance(value, dict) else value
        for prompt_id, value in prompts.items()
    }


def expand_system_prompt_refs(dataset, data_file: str | Path):
    if "system_prompt_id" not in dataset.column_names:
        return dataset

    prompts = _load_prompts(data_file)

    def expand(example):
        prompt_id = example["system_prompt_id"]
        system_prompt = prompts[prompt_id]
        return {
            "text": f"<|im_start|>system\n{system_prompt}<|im_end|>\n{example['text']}"
        }

    remove_columns = [name for name in dataset.column_names if name != "text"]
    return dataset.map(expand, remove_columns=remove_columns)