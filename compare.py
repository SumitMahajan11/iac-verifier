import json
import os

with open('benchmark/ground_truth.json') as f:
    gt = json.load(f)

def parse_checkov(path):
    if not os.path.exists(path):
        return {}
    for enc in ['utf-8', 'utf-16']:
        try:
            with open(path, encoding=enc) as f:
                data = f.read()
            s1 = data.find('{'); s2 = data.find('[')
            start = s1 if (s1 != -1 and (s2 == -1 or s1 < s2)) else s2
            e1 = data.rfind('}'); e2 = data.rfind(']')
            end = e1 if (e1 != -1 and (e2 == -1 or e1 > e2)) else e2
            return json.loads(data[start:end+1])
        except Exception:
            pass
    return {}

def parse_tfsec(path):
    if not os.path.exists(path):
        return {}
    for enc in ['utf-16', 'utf-8']:
        try:
            with open(path, encoding=enc) as f:
                return json.load(f)
        except Exception:
            pass
    return {}

checkov_files = [
    'checkov_terragoat_real.json',
    'checkov_sadcloud_real.json',
    'checkov_phase2.json',
    'checkov_phase3.json',
    'checkov_phase5.json',
    'checkov_phase6.json'
]

tfsec_files = [
    'tfsec_terragoat.json',
    'tfsec_sadcloud.json',
    'tfsec_phase2.json',
    'tfsec_phase3.json',
    'tfsec_phase5.json',
    'tfsec_phase6.json'
]

all_checkov = [parse_checkov(p) for p in checkov_files]
all_tfsec = [parse_tfsec(p) for p in tfsec_files]

def checkov_failed(file, res):
    filename = file.replace('\\', '/').split('/')[-1]
    for data in all_checkov:
        results = []
        if isinstance(data, list):
            for d in data:
                results.extend(d.get('results', {}).get('failed_checks', []))
        elif isinstance(data, dict):
            results = data.get('results', {}).get('failed_checks', [])
        for r in results:
            if r.get('resource') == res and r.get('file_path', '').endswith(filename):
                return True
    return False

def tfsec_failed(file, res):
    filename = file.replace('\\', '/').split('/')[-1]
    for data in all_tfsec:
        for r in data.get('results', []):
            if r.get('resource') == res and filename in r.get('location', {}).get('filename', ''):
                return True
    return False

print(f"{'Resource':<45} | {'Expected':<13} | {'Checkov':<7} | {'TFSec':<7}")
print("-" * 80)
for case in gt:
    file = case['file']
    res = case['resource_id']
    if case.get('ambiguity', {}).get('is_ambiguous'):
        continue
    c = checkov_failed(file, res)
    t = tfsec_failed(file, res)
    print(f"{res:<45} | {case['expected_engine_state']:<13} | {str(c):<7} | {str(t):<7}")
