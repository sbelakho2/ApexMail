"""Debug script to see actual model responses for failing tests."""
import sys, torch
from pathlib import Path
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel

BASE_DIR = Path('/workspace/ApexMail/apps/ai/training')
sys.path.insert(0, str(BASE_DIR))
from prompts import SYSTEM_PROMPT
MODEL_NAME = 'Qwen/Qwen2.5-7B-Instruct'
bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type='nf4', bnb_4bit_compute_dtype=torch.bfloat16)
model = AutoModelForCausalLM.from_pretrained(MODEL_NAME, quantization_config=bnb, device_map='auto', attn_implementation='sdpa', cache_dir='/workspace/.hf_home')
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, cache_dir='/workspace/.hf_home')
model = PeftModel.from_pretrained(model, str(BASE_DIR / 'output'))
model.eval()
print('MODEL LOADED')

def gen(q):
    msgs = [{'role':'system','content':SYSTEM_PROMPT},{'role':'user','content':q}]
    text = tokenizer.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
    inp = tokenizer(text, return_tensors='pt').to(model.device)
    with torch.no_grad():
        out = model.generate(**inp, max_new_tokens=512, temperature=0.3, top_p=0.9, do_sample=True, repetition_penalty=1.15, pad_token_id=tokenizer.eos_token_id)
    return tokenizer.decode(out[0][inp.input_ids.shape[-1]:], skip_special_tokens=True).strip()

tests = [
    (27, "I'll send exactly 10,001 emails on PAYG. What rate applies?"),
    (34, "My PAYG volume is 2 million emails/month. What's my rate?"),
    (38, "If I'm on Growth and send 150,000 emails, is the overage $25?"),
    (50, "What's the price-per-email on each plan?"),
    (177, "I need to send 100K emails/month, use DKIM, and run A/B tests. What plan and price?"),
    (262, "Our click rate is 3.5%. Is that good?"),
    (279, "My emails are returning 421 temporary failure codes. What does this mean?"),
    (364, "I found a bug where webhook events are being duplicated"),
    (368, "My account was suspended without explanation. Why?"),
    (460, "Цена тарифа Scale?"),
    (530, "Describe the Growth tier for me."),
    (566, "How do I start sending emails today?"),
    (601, "I send 80,000 emails and make 1.8 million API calls per month. What plan?"),
    (602, "Growth plan: 200K emails + 3M API calls. What's my total cost?"),
    (631, "Check domain health for all my domains and revoke my oldest API key"),
    (632, "Export all my data and then close my account"),
    (638, "Our marketing team needs A/B testing and we send 30,000 emails/month"),
]
for num, q in tests:
    r = gen(q)
    print(f'=== [{num}] Q: {q}')
    print(f'A: {r[:500]}')
    print()
