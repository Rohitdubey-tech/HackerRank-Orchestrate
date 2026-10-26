import os, sys, json, re, glob, sqlite3
import pandas as pd

def run_test():
    dataset_dir = "dataset"
    sample_reqs = pd.read_csv(os.path.join(dataset_dir, "sample_deletion_requests.csv"))
    sample_outs = pd.read_csv(os.path.join(dataset_dir, "sample_output.csv"))
    users_df = pd.read_csv(os.path.join(dataset_dir, "user_identities.csv"))
    audit_df = pd.read_csv(os.path.join(dataset_dir, "user_audit_log.csv"))
    rules_df = pd.read_csv(os.path.join(dataset_dir, "deletion_rules.csv"))
    sa_df = pd.read_csv(os.path.join(dataset_dir, "system_activity.csv"))
    sa_df['event_dt'] = pd.to_datetime(sa_df['event_time'])
    ev_files_df = pd.read_csv(os.path.join(dataset_dir, "evidence_files.csv"))
    
    # 1. Identity Manager
    user_info = {}
    for idx, r in users_df.iterrows():
        uid = r['user_id']
        user_info[uid] = {
            'user_id': uid,
            'name': r['name'].strip() if pd.notna(r['name']) else '',
            'email': r['email'].strip().lower() if pd.notna(r['email']) else '',
            'phone': r['phone'].strip() if pd.notna(r['phone']) else '',
            'email_hash': r['email_hash'].strip().lower() if pd.notna(r['email_hash']) else '',
            'all_emails': {r['email'].strip().lower()} if pd.notna(r['email']) else set(),
            'all_names': {r['name'].strip()} if pd.notna(r['name']) else set(),
            'all_phones': {r['phone'].strip()} if pd.notna(r['phone']) else set(),
            'all_hashes': {r['email_hash'].strip().lower()} if pd.notna(r['email_hash']) else set(),
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
            elif fn == 'email_hash':
                if pd.notna(r['old_value']): user_info[uid]['all_hashes'].add(str(r['old_value']).strip().lower())
                if pd.notna(r['new_value']): user_info[uid]['all_hashes'].add(str(r['new_value']).strip().lower())

    email_to_uid = {em: uid for uid, d in user_info.items() for em in d['all_emails']}

    # 2. Comprehensive Security Audit Record Mapping
    user_audit_map = {}
    for fp in glob.glob(os.path.join(dataset_dir, "evidence/**/*.json"), recursive=True):
        try:
            with open(fp) as f: data = json.load(f)
            def scan_j(obj):
                if isinstance(obj, dict):
                    rid = obj.get('resource_id')
                    uref = obj.get('subject_reference') or obj.get('subject_ref') or obj.get('user_id') or obj.get('customer_reference')
                    if rid and str(rid).startswith('audit_record_') and uref and str(uref).startswith('user_'):
                        user_audit_map[str(uref)] = str(rid)
                    for v in obj.values(): scan_j(v)
                elif isinstance(obj, list):
                    for item in obj: scan_j(item)
            scan_j(data)
        except: pass

    for fp in glob.glob(os.path.join(dataset_dir, "evidence/**/*.sql"), recursive=True):
        try:
            conn = sqlite3.connect(':memory:')
            conn.create_function('json_valid', 1, lambda x: 1)
            with open(fp, errors='ignore') as f: conn.executescript(f.read())
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            for tbl in [t[0] for t in cur.fetchall()]:
                cur.execute(f"PRAGMA table_info({tbl})")
                cols = [c[1] for c in cur.fetchall()]
                cur.execute(f"SELECT * FROM {tbl}")
                for row in cur.fetchall():
                    rd = dict(zip(cols, row))
                    rid = rd.get('resource_id')
                    rec_j = {}
                    if 'record_json' in rd:
                        try: rec_j = json.loads(rd['record_json'])
                        except: pass
                    uref = rec_j.get('subject_reference') or rec_j.get('user_id') or rd.get('customer_reference')
                    if rid and str(rid).startswith('audit_record_') and uref and str(uref).startswith('user_'):
                        user_audit_map[str(uref)] = str(rid)
        except: pass

    for fp in glob.glob(os.path.join(dataset_dir, "evidence/**/*.log"), recursive=True):
        try:
            with open(fp, errors='ignore') as f: lines = f.readlines()
            tr_u = {}
            tr_a = {}
            for line in lines:
                m_u = re.search(r'(?:subject_ref|subject_reference|lookup_key)[\":=\s]+["\']?(user_\d+)', line)
                m_a = re.search(r'(audit_record_\d+)', line)
                m_tr = re.search(r'(?:trace_id|traceId)[\":=\s]+["\']?([a-zA-Z0-9_\-]+)', line)
                if m_u and m_a: user_audit_map[m_u.group(1)] = m_a.group(1)
                if m_tr:
                    tr = m_tr.group(1)
                    if m_u: tr_u.setdefault(tr, set()).add(m_u.group(1))
                    if m_a: tr_a.setdefault(tr, set()).add(m_a.group(1))
            for tr, us in tr_u.items():
                if tr in tr_a:
                    for u in us:
                        for a in tr_a[tr]: user_audit_map[u] = a
        except: pass

    for fp in glob.glob(os.path.join(dataset_dir, "evidence/**/*.txt"), recursive=True):
        try:
            with open(fp, errors='ignore') as f:
                for line in f:
                    if 'audit_record_' in line and 'user_' in line:
                        m_a = re.search(r'(audit_record_\d+)', line)
                        m_u = re.search(r'(user_\d+)', line)
                        if m_a and m_u:
                            user_audit_map[m_u.group(1)] = m_a.group(1)
        except: pass

    print(f"Loaded {len(user_audit_map)} security audit records.")
    
    # Check sample outputs
    print("Done pre-scaffolding.")

if __name__ == '__main__':
    run_test()
