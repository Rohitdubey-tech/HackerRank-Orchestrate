"""
Full deletion audit agent matching test on sample cases.
"""
import os
import sys
import json
import re
import pandas as pd

sys.path.insert(0, os.path.dirname(__file__))
from evidence_parser import parse_all_evidence

def evaluate_samples():
    sample_reqs = pd.read_csv("dataset/sample_deletion_requests.csv")
    sample_outs = pd.read_csv("dataset/sample_output.csv")
    users_df = pd.read_csv("dataset/user_identities.csv")
    audit_df = pd.read_csv("dataset/user_audit_log.csv")
    sa_df = pd.read_csv("dataset/system_activity.csv")
    ev_files_df = pd.read_csv("dataset/evidence_files.csv")
    rules_df = pd.read_csv("dataset/deletion_rules.csv")
    
    # 1. Identity index
    user_info = {}
    for idx, r in users_df.iterrows():
        uid = r['user_id']
        user_info[uid] = {
            'user_id': uid,
            'name': r['name'].strip() if pd.notna(r['name']) else '',
            'email': r['email'].strip().lower() if pd.notna(r['email']) else '',
            'phone': r['phone'].strip() if pd.notna(r['phone']) else '',
            'email_hash': r['email_hash'].strip() if pd.notna(r['email_hash']) else '',
            'all_emails': {r['email'].strip().lower()} if pd.notna(r['email']) else set(),
            'all_names': {r['name'].strip()} if pd.notna(r['name']) else set(),
            'all_phones': {r['phone'].strip()} if pd.notna(r['phone']) else set(),
        }
        
    for idx, r in audit_df.iterrows():
        uid = r['user_id']
        if uid in user_info:
            fn = r['field_name']
            if fn == 'email':
                if pd.notna(r['old_value']): user_info[uid]['all_emails'].add(str(r['old_value']).strip().lower())
                if pd.notna(r['new_value']): user_info[uid]['all_emails'].add(str(r['new_value']).strip().lower())
            elif fn == 'name':
                if pd.notna(r['old_value']): user_info[uid]['all_names'].add(str(r['old_value']).strip())
                if pd.notna(r['new_value']): user_info[uid]['all_names'].add(str(r['new_value']).strip())
            elif fn == 'phone':
                if pd.notna(r['old_value']): user_info[uid]['all_phones'].add(str(r['old_value']).strip())
                if pd.notna(r['new_value']): user_info[uid]['all_phones'].add(str(r['new_value']).strip())
                
    email_to_uid = {em: uid for uid, d in user_info.items() for em in d['all_emails']}
    
    # 2. Parse evidence
    all_evidence = parse_all_evidence("dataset")
    
    # Map evidence file capture times
    ev_cap_map = dict(zip(ev_files_df['file_id'], ev_files_df['captured_at']))
    ev_path_map = dict(zip(ev_files_df['file_id'], ev_files_df['file_path']))
    
    print(f"Loaded {len(all_evidence)} parsed evidence records.")
    
    # Test on all 32 sample cases
    matches = 0
    total = len(sample_reqs)
    
    for idx, req_row in sample_reqs.iterrows():
        cid = req_row['case_id']
        email = req_row['email'].strip().lower()
        uid = email_to_uid[email]
        u = user_info[uid]
        audit_at = req_row['audit_at']
        rep_at = req_row['reported_at']
        
        expected_row = sample_outs[sample_outs['case_id'] == cid].iloc[0]
        expected_status = expected_row['deletion_status']
        expected_steps = json.loads(expected_row['steps_json'])
        
        # Check evidence records matching user
        u_records = []
        for er in all_evidence:
            if er['captured_at'] > audit_at: continue
            # Check match
            match = False
            if uid in er['identifiers']: match = True
            for em in u['all_emails']:
                if em in er['identifiers']: match = True
            for ph in u['all_phones']:
                if ph in er['identifiers']: match = True
                
            if match:
                u_records.append(er)
                
        # Group by resource_id
        res_map = {}
        for ur in u_records:
            rid = ur['resource_id']
            if rid not in res_map or ur['captured_at'] > res_map[rid]['captured_at']:
                res_map[rid] = ur
                
        # Print comparison
        print(f"{cid} ({uid}): expected={expected_status} ({len(expected_steps)} steps), matched_resources={list(res_map.keys())}")

if __name__ == "__main__":
    evaluate_samples()
