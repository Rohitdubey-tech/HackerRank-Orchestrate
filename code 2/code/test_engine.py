"""
Audit Engine Prototype and Verification against sample_output.csv
"""
import os
import json
import re
import pandas as pd

def load_data(dataset_dir="dataset"):
    sample_reqs = pd.read_csv(os.path.join(dataset_dir, "sample_deletion_requests.csv"))
    sample_outs = pd.read_csv(os.path.join(dataset_dir, "sample_output.csv"))
    users_df = pd.read_csv(os.path.join(dataset_dir, "user_identities.csv"))
    audit_df = pd.read_csv(os.path.join(dataset_dir, "user_audit_log.csv"))
    rules_df = pd.read_csv(os.path.join(dataset_dir, "deletion_rules.csv"))
    sa_df = pd.read_csv(os.path.join(dataset_dir, "system_activity.csv"))
    ev_files_df = pd.read_csv(os.path.join(dataset_dir, "evidence_files.csv"))
    
    with open("code/image_ocr_cache.json") as f:
        ocr_cache = json.load(f)
    with open("code/pdf_text_cache.json") as f:
        pdf_cache = json.load(f)
        
    return sample_reqs, sample_outs, users_df, audit_df, rules_df, sa_df, ev_files_df, ocr_cache, pdf_cache

print("Loaded test runner scaffold.")
