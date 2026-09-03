import json, os

def parse_checkov(path):
    if not os.path.exists(path): return {}
    for enc in ['utf-8', 'utf-16']:
        try:
            with open(path, encoding=enc) as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def parse_tfsec(path):
    if not os.path.exists(path): return {}
    for enc in ['utf-16', 'utf-8']:
        try:
            with open(path, encoding=enc) as f:
                return json.load(f)
        except Exception:
            pass
    return {}

c3 = parse_checkov('checkov_phase3.json')
c6 = parse_checkov('checkov_phase6.json')
t3 = parse_tfsec('tfsec_phase3.json')
t6 = parse_tfsec('tfsec_phase6.json')

print('=== CHECKOV PHASE 3 FAILED CHECKS ===')
results3 = c3 if isinstance(c3, list) else [c3]
for d in results3:
    for r in d.get('results', {}).get('failed_checks', []):
        print(f"{r.get('check_id')}: {r.get('resource')} ({r.get('file_path')})")

print('\n=== CHECKOV PHASE 6 FAILED CHECKS ===')
results6 = c6 if isinstance(c6, list) else [c6]
for d in results6:
    for r in d.get('results', {}).get('failed_checks', []):
        print(f"{r.get('check_id')}: {r.get('resource')} ({r.get('file_path')})")

print('\n=== TFSEC PHASE 3 RESULTS ===')
for r in t3.get('results', []):
    print(f"{r.get('rule_id')}: {r.get('resource')} ({r.get('location', {}).get('filename')})")

print('\n=== TFSEC PHASE 6 RESULTS ===')
for r in t6.get('results', []):
    print(f"{r.get('rule_id')}: {r.get('resource')} ({r.get('location', {}).get('filename')})")
