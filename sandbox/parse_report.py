import json
with open('dlp_report.json') as f:
    res = json.load(f)
ok = [r for r in res if r['ok']]
fp = [r for r in res if r['expected']=='PASS' and r['actual']!='PASS']
fn = [r for r in res if r['expected']!='PASS' and r['actual']=='PASS']
print(f"Accuracy: {len(ok)}/{len(res)} = {round(len(ok)/len(res)*100,1)}%")
print(f"False Positives: {len(fp)}")
print(f"False Negatives: {len(fn)}")
if fp:
    print("FPs:")
    for r in fp:
        print(f"  #{r['id']} [{r['category']}] actual={r['actual']} score={r['score']}  {r['prompt'][:60]}")
if fn:
    print("FNs:")
    for r in fn:
        print(f"  #{r['id']} [{r['category']}] expected={r['expected']} score={r['score']}  {r['prompt'][:60]}")
cats = {}
for r in res:
    cats.setdefault(r['category'],[]).append(r)
print("By category:")
for cat, rlist in sorted(cats.items()):
    ok_n = sum(1 for r in rlist if r['ok'])
    fp_n = sum(1 for r in rlist if r['expected']=='PASS' and r['actual']!='PASS')
    fn_n = sum(1 for r in rlist if r['expected']!='PASS' and r['actual']=='PASS')
    print(f"  {cat:16s}: {ok_n}/{len(rlist)}  FP={fp_n} FN={fn_n}")
