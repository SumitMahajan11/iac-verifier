import json

with open('checkov_sadcloud_real.json', encoding='utf-16') as f: data = f.read()
s1 = data.find('{'); s2 = data.find('[')
start = s1 if (s1 != -1 and (s2 == -1 or s1 < s2)) else s2
e1 = data.rfind('}'); e2 = data.rfind(']')
end = e1 if (e1 != -1 and (e2 == -1 or e1 > e2)) else e2
data = json.loads(data[start:end+1])

results = []
if isinstance(data, list):
    for d in data: results.extend(d.get('results', {}).get('failed_checks', []))
else:
    results = data.get('results', {}).get('failed_checks', [])
        
for r in results:
    if r.get('resource') == 'aws_security_group.unneeded_security_group':
        print(f"Check: {r.get('check_id')} - {r.get('check_name')}")
