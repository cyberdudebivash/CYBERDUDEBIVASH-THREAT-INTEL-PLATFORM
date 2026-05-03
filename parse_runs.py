import json, sys
d = json.load(open('C:/temp/runs.json'))
for r in d['workflow_runs']:
    print(r['id'], '|', r['name'][:35], '|', r['status'], '|', str(r['conclusion']), '|', r['head_sha'][:10], '|', r['created_at'])
