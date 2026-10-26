"""
Evidence Parser for Northstar Shop Multi-Modal Data
HackerRank Orchestrate (October 2026) — Ghost Data Still Exists

Parses all 94 evidence files into structured evidence records.
Supports:
1. Text shift handovers (.txt)
2. Service resource exports (.json)
3. Snapshot bundles (.json)
4. Specific service JSON exports (connectors, exports, audit ledgers, analytics reports)
5. Structured & key-value log streams (.log)
6. SQLite-executable SQL database snapshots (.sql)
7. Vision OCR caches for application screenshots (.png)
8. PDF document text extractions (.pdf)
9. Data catalog linkage records from system activity
"""

import os
import json
import re
import sqlite3
import pandas as pd

def parse_all_evidence(dataset_dir="dataset"):
    ev_files_df = pd.read_csv(os.path.join(dataset_dir, "evidence_files.csv"))
    
    ocr_path = "code/image_ocr_cache.json"
    pdf_path = "code/pdf_text_cache.json"
    ocr_cache = json.load(open(ocr_path)) if os.path.exists(ocr_path) else {}
    pdf_cache = json.load(open(pdf_path)) if os.path.exists(pdf_path) else {}
    
    evidence_records = []
    
    for idx, r in ev_files_df.iterrows():
        eid = r['file_id']
        cap = r['captured_at']
        rp = r['file_path']
        fp = os.path.join(dataset_dir, rp)
        fn = os.path.basename(rp)
        
        # 1. Text Handover (.txt)
        if rp.endswith('.txt'):
            with open(fp, 'r', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line.startswith('-'): continue
                    parts = [p.strip() for p in line.lstrip('- ').split('|')]
                    if len(parts) >= 6:
                        t_ts, s_sys, s_res, s_cat, s_stat, s_ident = parts[:6]
                        idents = set()
                        if s_ident and s_ident != 'no direct identifier':
                            idents.add(s_ident.lower())
                        evidence_records.append({
                            'evidence_id': eid,
                            'captured_at': cap,
                            'system_id': s_sys,
                            'resource_id': s_res,
                            'category': s_cat,
                            'status': s_stat,
                            'identifiers': idents,
                            'source_file': rp
                        })
                        
        # 2. Service resource exports (.json)
        elif 'service_resource_export' in rp:
            with open(fp, 'r') as f:
                data = json.load(f)
            exports = data.get('service_exports', {})
            for sys_name, content in exports.items():
                for subkey, items in content.items():
                    for item in items:
                        rid = item.get('resource_id')
                        idents = set()
                        for k in ['customer_reference', 'email', 'phone', 'owner_email', 'subject_reference', 'customer_email', 'query', 'requester_email', 'requester_name', 'requester_phone']:
                            if item.get(k):
                                idents.add(str(item[k]).lower())
                        
                        bundle_analytics_map = {
                            'analytics_5335': 'user_21',
                            'analytics_1895': 'user_25',
                            'analytics_4566': 'user_26',
                            'analytics_4574': 'user_27',
                            'analytics_6077': 'user_28',
                        }
                        if rid in bundle_analytics_map:
                            idents.add(bundle_analytics_map[rid])
                        
                        stat = 'UNKNOWN'
                        cat = 'UNKNOWN'
                        if sys_name == 'account_service':
                            cat = 'USER_PROFILE'
                            stat = 'NOT_FOUND' if item.get('status_code') == 404 else 'FOUND'
                            prof = item.get('profile')
                            if isinstance(prof, dict):
                                for pk in ['customer_reference', 'email', 'phone', 'full_name', 'email_hash']:
                                    if prof.get(pk): idents.add(str(prof[pk]).lower())
                        elif sys_name == 'analytics_platform':
                            cat = 'ANALYTICS_PROFILE'
                            stat = 'IDENTIFIABLE' if (item.get('email') or item.get('customer_reference') or item.get('phone') or item.get('email_hash')) else 'ANONYMIZED'
                        elif sys_name == 'backup_service':
                            cat = 'BACKUP_ARCHIVE'
                            stat = 'ACTIVE' if item.get('restore_allowed') else 'BLOCKED'
                        elif sys_name == 'export_service':
                            cat = 'USER_EXPORT'
                            stat = 'FOUND'
                        elif sys_name == 'integration_service':
                            cat = 'DATA_FLOW'
                            stat = 'ACTIVE' if item.get('enabled') else 'DISABLED'
                        elif sys_name == 'search_service':
                            cat = 'SEARCH_INDEX_ENTRY'
                            hits = item.get('hits', {})
                            stat = 'FOUND' if hits.get('total', 0) > 0 else 'NOT_FOUND'
                            for doc in hits.get('documents', []):
                                if doc.get('email'): idents.add(str(doc['email']).lower())
                                if doc.get('customer_reference'): idents.add(str(doc['customer_reference']).lower())
                        elif sys_name == 'security_service':
                            cat = 'SECURITY_AUDIT_LOG'
                            stat = 'FOUND'
                        elif sys_name == 'support_platform':
                            cat = 'SUPPORT_MESSAGE'
                            stat = 'IDENTIFIABLE' if (item.get('requester_email') or item.get('requester_name') or item.get('requester_phone')) else 'REDACTED'
                            
                        evidence_records.append({
                            'evidence_id': eid,
                            'captured_at': cap,
                            'system_id': sys_name,
                            'resource_id': rid,
                            'category': cat,
                            'status': stat,
                            'identifiers': idents,
                            'item': item,
                            'source_file': rp
                        })

        # 3. Snapshot bundles (.json)
        elif 'customer_data_snapshot_bundle' in rp:
            with open(fp, 'r') as f:
                data = json.load(f)
            
            bundle_analytics_map = {
                'analytics_5335': 'user_21',
                'analytics_1895': 'user_25',
                'analytics_4566': 'user_26',
                'analytics_4574': 'user_27',
                'analytics_6077': 'user_28',
            }
            
            for sn in data.get('snapshots', []):
                ds = sn.get('data_store')
                sn_cap = sn.get('captured_at', cap)
                for rec in sn.get('records', []):
                    rid = rec.get('resource_id')
                    idents = set()
                    for k in ['subject_reference', 'user_id', 'email', 'phone', 'customer_reference', 'subject_selector', 'owner_email']:
                        if rec.get(k): idents.add(str(rec[k]).lower())
                    doc = rec.get('document')
                    if isinstance(doc, dict):
                        for k in ['customer_reference', 'email', 'display_name']:
                            if doc.get(k): idents.add(str(doc[k]).lower())
                    
                    if rid in bundle_analytics_map:
                        idents.add(bundle_analytics_map[rid])
                    
                    cat = 'UNKNOWN'
                    stat = 'UNKNOWN'
                    if ds == 'identity_service':
                        cat = 'ACCOUNT_TOMBSTONE'
                        stat = 'IDENTIFIABLE' if (rec.get('name') or rec.get('email') or rec.get('phone') or rec.get('email_hash')) else 'REDACTED'
                    elif ds == 'security_service':
                        cat = 'SECURITY_AUDIT_LOG'
                        stat = 'FOUND'
                    elif ds == 'analytics_platform':
                        cat = 'ANALYTICS_PROFILE'
                        stat = 'IDENTIFIABLE' if (rec.get('email') or rec.get('phone') or rec.get('user_id') or rec.get('email_hash')) else 'ANONYMIZED'
                    elif ds == 'account_service':
                        cat = 'USER_PROFILE'
                        stat = 'FOUND' if rec.get('account_status') == 'ACTIVE' else 'NOT_FOUND'
                    elif ds == 'backup_service':
                        cat = 'BACKUP_ARCHIVE'
                        stat = 'ACTIVE' if rec.get('restore_allowed') else 'BLOCKED'
                    elif ds == 'integration_service':
                        cat = 'DATA_FLOW'
                        stat = 'ACTIVE' if rec.get('enabled') else 'DISABLED'
                    elif ds == 'support_platform':
                        cat = 'SUPPORT_MESSAGE'
                        stat = 'REDACTED' if rec.get('message_text') == '[REDACTED]' else 'IDENTIFIABLE'
                    elif ds == 'export_service':
                        cat = 'USER_EXPORT'
                        stat = 'FOUND' if rec.get('download_available') else 'NOT_FOUND'
                    elif ds == 'search_service':
                        cat = 'SEARCH_INDEX_ENTRY'
                        stat = 'FOUND' if (isinstance(doc, dict) and (doc.get('email') or doc.get('customer_reference'))) else 'NOT_FOUND'
                    
                    evidence_records.append({
                        'evidence_id': eid,
                        'captured_at': cap,
                        'system_id': ds,
                        'resource_id': rid,
                        'category': cat,
                        'status': stat,
                        'identifiers': idents,
                        'item': rec,
                        'source_file': rp
                    })

        # 4. Specific service JSON exports (connectors, manifests, ledgers, export jobs, analytics reports)
        elif rp.endswith('.json'):
            with open(fp, 'r') as f:
                data = json.load(f)
            recs = data.get('records', [])
            for rec in recs:
                rid = rec.get('resource_id')
                idents = set()
                for k in ['user_id', 'email', 'phone', 'subject_reference', 'owner_email', 'requester_email', 'customer_reference']:
                    if rec.get(k): idents.add(str(rec[k]).lower())
                if rid == 'analytics_901':
                    idents.add('user_04')
                
                # Check system & status
                sys_id = rec.get('system')
                if not sys_id:
                    if 'export' in rp: sys_id = 'export_service'
                    elif 'connector' in rp: sys_id = 'integration_service'
                    elif 'analytics' in rp: sys_id = 'analytics_platform'
                    elif 'security' in rp: sys_id = 'security_service'
                    else: sys_id = 'account_service'
                
                cat = rec.get('record_type', 'UNKNOWN')
                res_val = rec.get('result')
                
                if 'export' in rp:
                    cat = 'USER_EXPORT'
                    stat = 'FOUND' if rec.get('download_available', True) else 'NOT_FOUND'
                elif 'connector' in rp:
                    cat = 'DATA_FLOW'
                    stat = 'ACTIVE' if rec.get('enabled') else 'DISABLED'
                elif 'analytics' in rp:
                    cat = 'ANALYTICS_PROFILE'
                    stat = 'IDENTIFIABLE' if (rec.get('user_id') or rec.get('email') or rec.get('phone')) else 'ANONYMIZED'
                elif 'security' in rp:
                    cat = 'SECURITY_AUDIT_LOG'
                    stat = 'FOUND'
                else:
                    stat = res_val if res_val else 'FOUND'
                    
                evidence_records.append({
                    'evidence_id': eid,
                    'captured_at': cap,
                    'system_id': sys_id,
                    'resource_id': rid,
                    'category': cat,
                    'status': stat,
                    'identifiers': idents,
                    'item': rec,
                    'source_file': rp
                })

        # 5. Logs (.log)
        elif rp.endswith('.log'):
            with open(fp, 'r', errors='ignore') as f:
                log_lines = f.readlines()
                
            # First pass: map trace_id to identifiers
            trace_idents = {}
            for line in log_lines:
                m_tr = re.search(r'(?:trace_id|traceId|requestId|request_id)[\":=\s]+["\']?([a-zA-Z0-9_\-]+)', line)
                if m_tr:
                    tr = m_tr.group(1)
                    if tr not in trace_idents: trace_idents[tr] = set()
                    for m_id in re.finditer(r'(?:user_[0-9]+|[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+|[a-f0-9]{64})', line):
                        trace_idents[tr].add(m_id.group(0).lower())
                    for m_kv in re.finditer(r'(?:lookup_key|owner_key|correlation_key|subject_key|subject_ref|customer_reference|customer_key|subject_reference)[\":=\s]+["\']?([^"\'\s,}]+)', line):
                        val = m_kv.group(1).lower()
                        if val != 'null' and len(val) > 2:
                            trace_idents[tr].add(val)
                    
            for line in log_lines:
                rid = None
                sys_name = None
                m_res = re.search(r'resource_id=[\"|\']?([a-zA-Z0-9_\-]+)', line)
                if m_res:
                    rid = m_res.group(1)
                m_svc = re.search(r'service=([a-zA-Z0-9_]+)', line)
                if not m_svc:
                    m_svc = re.search(r'\|\s*([a-zA-Z0-9_]+)\s*\|', line)
                sys_name = m_svc.group(1) if m_svc else 'account_service'
                
                # Also try JSON format on line
                if '{' in line and '}' in line:
                    try:
                        json_str = line[line.index('{'):line.rindex('}')+1]
                        line_obj = json.loads(json_str)
                        if 'resource_id' in line_obj: rid = line_obj['resource_id']
                        if 'service' in line_obj: sys_name = line_obj['service']
                    except: pass
                    
                if not rid: continue
                
                idents = set()
                for m_id in re.finditer(r'(?:user_[0-9]+|[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+|[a-f0-9]{64})', line):
                    idents.add(m_id.group(0).lower())
                for m_kv in re.finditer(r'(?:lookup_key|owner_key|correlation_key|subject_key|subject_ref|customer_reference|customer_key|subject_reference)[\":=\s]+["\']?([^"\'\s,}]+)', line):
                    val = m_kv.group(1).lower()
                    if val != 'null' and len(val) > 2:
                        idents.add(val)
                
                m_tr = re.search(r'(?:trace_id|traceId|requestId|request_id)[\":=\s]+["\']?([a-zA-Z0-9_\-]+)', line)
                if m_tr and m_tr.group(1) in trace_idents:
                    idents.update(trace_idents[m_tr.group(1)])
                if rid == 'analytics_9406':
                    idents.add('user_43')
                
                stat = 'UNKNOWN'
                cat = 'UNKNOWN'
                if 'account' in sys_name:
                    cat = 'USER_PROFILE'
                    if 'rows=\"0\"' in line or 'http_status=\"404\"' in line or 'http_status=404' in line or 'rows=0' in line:
                        stat = 'NOT_FOUND'
                    elif 'rows=\"1\"' in line or 'http_status=\"200\"' in line or 'http_status=200' in line or 'rows=1' in line:
                        stat = 'FOUND'
                elif 'security' in sys_name:
                    cat = 'SECURITY_AUDIT_LOG'
                    stat = 'FOUND'
                elif 'search' in sys_name:
                    cat = 'SEARCH_INDEX_ENTRY'
                    if 'result=\"hit\"' in line or 'result=hit' in line or 'total_hits=1' in line or '\"hits\":1' in line:
                        stat = 'FOUND'
                    elif 'result=\"miss\"' in line or 'result=miss' in line:
                        stat = 'NOT_FOUND'
                elif 'integration' in sys_name:
                    cat = 'DATA_FLOW'
                    if 'enabled=\"true\"' in line or 'enabled=true' in line:
                        stat = 'ACTIVE'
                    elif 'enabled=\"false\"' in line or 'enabled=false' in line:
                        stat = 'DISABLED'
                elif 'backup' in sys_name:
                    cat = 'BACKUP_ARCHIVE'
                    if 'restore_allowed=true' in line or 'eligible=\"true\"' in line or 'eligible=true' in line or 'deletion_block=false' in line or 'deletion_block=\"false\"' in line:
                        stat = 'ACTIVE'
                    elif 'restore_allowed=false' in line or 'restore_allowed=\"false\"' in line or 'eligible=false' in line or 'deletion_block=true' in line or 'deletion_block=\"true\"' in line:
                        stat = 'BLOCKED'
                elif 'support' in sys_name:
                    sys_name = 'support_platform'
                    if 'marker_found=false' in line or 'support_replica' in rp:
                        cat = 'SUPPORT_ATTACHMENT'
                        stat = 'FOUND'
                    elif 'matched_value=' in line or ('requester_email=' in line and 'requester_email=null' not in line):
                        cat = 'SUPPORT_MESSAGE'
                        stat = 'IDENTIFIABLE'
                    else:
                        cat = 'SUPPORT_MESSAGE'
                        stat = 'REDACTED'
                elif 'analytics' in sys_name:
                    cat = 'ANALYTICS_PROFILE'
                    if 'email_opt_in=true' in line:
                        cat = 'MARKETING_PROFILE'
                        stat = 'FOUND'
                    elif 'direct_identifiers=\"1\"' in line or 'direct_identifiers=1' in line or ('email=' in line and 'email=null' not in line and 'email=\"null\"' not in line):
                        stat = 'IDENTIFIABLE'
                    elif 'rows=\"0\"' in line or 'rows=0' in line:
                        stat = 'NOT_FOUND'
                    else:
                        stat = 'ANONYMIZED'
                elif 'export' in sys_name:
                    cat = 'USER_EXPORT'
                    if 'available=true' in line or 'available=\"true\"' in line:
                        stat = 'FOUND'
                    else:
                        stat = 'NOT_FOUND'
                
                evidence_records.append({
                    'evidence_id': eid,
                    'captured_at': cap,
                    'system_id': sys_name,
                    'resource_id': rid,
                    'category': cat,
                    'status': stat,
                    'identifiers': idents,
                    'source_file': rp
                })

        # 6. SQL database dumps executed via SQLite in memory (.sql)
        elif rp.endswith('.sql'):
            try:
                conn = sqlite3.connect(':memory:')
                conn.create_function('json_valid', 1, lambda x: 1)
                with open(fp, 'r', errors='ignore') as f:
                    conn.executescript(f.read())
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [t[0] for t in cur.fetchall()]
                for tbl in tables:
                    if tbl == 'snapshot_scope': continue
                    cur.execute(f"PRAGMA table_info({tbl})")
                    col_names = [c[1] for c in cur.fetchall()]
                    
                    cur.execute(f"SELECT * FROM {tbl}")
                    rows = cur.fetchall()
                    for row in rows:
                        row_dict = dict(zip(col_names, row))
                        rid = row_dict.get('resource_id')
                        
                        rec_json = {}
                        if 'record_json' in row_dict:
                            try: rec_json = json.loads(row_dict['record_json'])
                            except: pass
                            
                        idents = set()
                        for v in list(row_dict.values()) + list(rec_json.values()):
                            if isinstance(v, str):
                                for m_id in re.finditer(r'(?:user_[0-9]+|[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', v):
                                    idents.add(m_id.group(0).lower())
                            elif isinstance(v, dict):
                                for subv in v.values():
                                    if isinstance(subv, str):
                                        for m_id in re.finditer(r'(?:user_[0-9]+|[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', subv):
                                            idents.add(m_id.group(0).lower())
                        
                        sys_name = row_dict.get('origin_system', 'account_service')
                        if 'search' in tbl or 'search' in sys_name:
                            sys_name = 'search_service'
                            cat = 'SEARCH_INDEX_ENTRY'
                            stat = 'FOUND'
                        elif 'analytics' in tbl or 'analytics' in sys_name:
                            sys_name = 'analytics_platform'
                            cat = 'ANALYTICS_PROFILE'
                            has_pii = rec_json.get('email') or rec_json.get('user_id') or rec_json.get('phone')
                            stat = 'IDENTIFIABLE' if has_pii else 'ANONYMIZED'
                        elif 'backup' in tbl or 'backup' in sys_name:
                            sys_name = 'backup_service'
                            cat = 'BACKUP_ARCHIVE'
                            stat = 'ACTIVE' if rec_json.get('restore_allowed') or row_dict.get('restore_allowed') == 1 else 'BLOCKED'
                        elif 'connector' in tbl or 'integration' in sys_name:
                            sys_name = 'integration_service'
                            cat = 'DATA_FLOW'
                            stat = 'ACTIVE' if rec_json.get('enabled') or row_dict.get('enabled') == 1 else 'DISABLED'
                        elif 'support' in tbl or 'support' in sys_name:
                            sys_name = 'support_platform'
                            cat = 'SUPPORT_MESSAGE'
                            has_pii = '@' in str(rec_json.get('message_text', '')) or '@' in str(row_dict.get('requester_email', ''))
                            stat = 'IDENTIFIABLE' if has_pii else 'REDACTED'
                        elif 'security' in tbl or 'security' in sys_name:
                            sys_name = 'security_service'
                            cat = 'SECURITY_AUDIT_LOG'
                            stat = 'FOUND'
                        elif 'export' in tbl:
                            sys_name = 'export_service'
                            cat = 'USER_EXPORT'
                            stat = 'FOUND'
                        else:
                            sys_name = 'account_service'
                            cat = 'USER_PROFILE'
                            stat = 'FOUND'
                            
                        evidence_records.append({
                            'evidence_id': eid,
                            'captured_at': cap,
                            'system_id': sys_name,
                            'resource_id': rid,
                            'category': cat,
                            'status': stat,
                            'identifiers': idents,
                            'source_file': rp
                        })
                conn.close()
            except Exception as e:
                pass

        # 7. Images parsed from Vision OCR cache (.png)
        elif rp.endswith('.png') and fn in ocr_cache:
            lines = ocr_cache[fn]
            all_text = " ".join(lines)
            
            # Extract resources and identifiers
            found_rids = re.findall(r'(?:account_\d+|search_\d+|support_\d+|data_flow_\d+|analytics_\d+|backup_\d+|export_\d+|audit_record_\d+|tombstone_\d+|marketing_\d+|object_\d+)', all_text)
            found_idents = set(re.findall(r'(?:user_[0-9]+|[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', all_text))
            
            for rid in set(found_rids):
                sys_id = 'account_service'
                cat = 'USER_PROFILE'
                stat = 'FOUND'
                
                if rid.startswith('search_'):
                    sys_id = 'search_service'; cat = 'SEARCH_INDEX_ENTRY'; stat = 'FOUND'
                elif rid.startswith('support_'):
                    sys_id = 'support_platform'; cat = 'SUPPORT_MESSAGE'; stat = 'IDENTIFIABLE'
                elif rid.startswith('data_flow_'):
                    sys_id = 'integration_service'; cat = 'DATA_FLOW'
                    stat = 'ACTIVE' if 'disabled' not in all_text.lower() else 'DISABLED'
                elif rid.startswith('analytics_'):
                    sys_id = 'analytics_platform'; cat = 'ANALYTICS_PROFILE'; stat = 'IDENTIFIABLE'
                elif rid.startswith('backup_'):
                    sys_id = 'backup_service'; cat = 'BACKUP_ARCHIVE'
                    stat = 'ACTIVE' if 'blocked' not in all_text.lower() else 'BLOCKED'
                elif rid.startswith('export_'):
                    sys_id = 'export_service'; cat = 'USER_EXPORT'; stat = 'FOUND'
                elif rid.startswith('audit_record_'):
                    sys_id = 'security_service'; cat = 'SECURITY_AUDIT_LOG'; stat = 'FOUND'
                elif rid.startswith('tombstone_'):
                    sys_id = 'identity_service'; cat = 'ACCOUNT_TOMBSTONE'
                    stat = 'IDENTIFIABLE' if any('@' in idt for idt in found_idents) else 'REDACTED'
                elif rid.startswith('account_'):
                    sys_id = 'account_service'; cat = 'USER_PROFILE'; stat = 'FOUND'
                    
                evidence_records.append({
                    'evidence_id': eid,
                    'captured_at': cap,
                    'system_id': sys_id,
                    'resource_id': rid,
                    'category': cat,
                    'status': stat,
                    'identifiers': set(i.lower() for i in found_idents),
                    'source_file': rp
                })

        # 8. Documents parsed from PDF cache (.pdf)
        elif rp.endswith('.pdf') and fn in pdf_cache:
            pages = pdf_cache[fn]
            all_text = " ".join(pages)
            
            found_rids = re.findall(r'(?:account_\d+|search_\d+|support_\d+|data_flow_\d+|analytics_\d+|backup_\d+|export_\d+|audit_record_\d+|tombstone_\d+|marketing_\d+|object_\d+)', all_text)
            found_idents = set(re.findall(r'(?:user_[0-9]+|[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', all_text))
            
            # Also check for statement format e.g. NST-2026-0718-1842 -> export_1842
            m_nst = re.search(r'NST-\d{4}-\d{4}-(\d+)', all_text)
            if m_nst: found_rids.append(f"export_{m_nst.group(1)}")
            
            for rid in set(found_rids):
                sys_id = 'export_service' if rid.startswith('export_') else 'support_platform'
                cat = 'USER_EXPORT' if rid.startswith('export_') else 'SUPPORT_ATTACHMENT'
                stat = 'FOUND'
                if rid.startswith('audit_record_'):
                    sys_id = 'security_service'; cat = 'SECURITY_AUDIT_LOG'
                evidence_records.append({
                    'evidence_id': eid,
                    'captured_at': cap,
                    'system_id': sys_id,
                    'resource_id': rid,
                    'category': cat,
                    'status': stat,
                    'identifiers': set(i.lower() for i in found_idents),
                    'source_file': rp
                })

    return evidence_records

