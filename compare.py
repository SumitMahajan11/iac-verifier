import json
import os
with open('benchmark/ground_truth.json') as f: gt = json.load(f)

def parse_checkov(path):
    with open(path, encoding='utf-16') as f:
        data = f.read()
    s1 = data.find('{'); s2 = data.find('[')
    start = s1 if (s1 != -1 and (s2 == -1 or s1 < s2)) else s2
    e1 = data.rfind('}'); e2 = data.rfind(']')
    end = e1 if (e1 != -1 and (e2 == -1 or e1 > e2)) else e2
    try:
        return json.loads(data[start:end+1])
    except:
        return {}

def checkov_failed(data, file, res):
    results = []
    if isinstance(data, list):
        for d in data: results.extend(d.get('results', {}).get('failed_checks', []))
    else:
        results = data.get('results', {}).get('failed_checks', [])
        
    for r in results:
        # Checkov prepends '/' or '\' to file_path
        filename = file.replace('\\', '/').split('/')[-1]
        if r.get('resource') == res and r.get('file_path', '').endswith(filename):
            return True
    return False

def parse_tfsec(path):
    with open(path, encoding='utf-16') as f:
        try: return json.load(f)
        except Exception: pass
    with open(path, encoding='utf-8') as f:
        return json.load(f)

def tfsec_failed(data, file, res):
    filename = file.replace('\\', '/').split('/')[-1]
    for r in data.get('results', []):
        if r.get('resource') == res and filename in r.get('location', {}).get('filename', ''): return True
    return False

cg = parse_checkov('checkov_terragoat_real.json')
cs = parse_checkov('checkov_sadcloud_real.json')
tg = parse_tfsec('tfsec_terragoat.json')
ts = parse_tfsec('tfsec_sadcloud.json')

print(f"{'Resource':<45} | {'Expected':<13} | {'Checkov':<7} | {'TFSec':<7}")
print("-" * 80)
for case in gt:
    file = case['file']
    res = case['resource_id']
    if 'terragoat' in file:
        c = checkov_failed(cg, file, res)
        t = tfsec_failed(tg, file, res)
    elif 'sadcloud' in file:
        c = checkov_failed(cs, file, res)
        t = tfsec_failed(ts, file, res)
    else:
        continue
    print(f"{res:<45} | {case['expected_engine_state']:<13} | {str(c):<7} | {str(t):<7}")
