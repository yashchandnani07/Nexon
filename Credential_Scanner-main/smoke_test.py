"""
Quick smoke test for patterns.py (detect-secrets + patterns.json) 
and ner_detector.py (BERT + NLTK fallback).
Run with: python smoke_test.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

TEST_TEXT = """
Dear John Smith,

Your Example Bank account has been suspended. Please verify immediately.
Here are your new login credentials:
  username: jsmith@Example Bank.com
  password: MySecretPass99!

Your OTP code is 847231.

AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

Your Visa card: 4111 1111 1111 1111
CVV: 123   Expires: 12/26

Account Number: 12345678   Sort Code: 20-00-00
IBAN: GB29NWBK60161331926819

Regards,
Example Bank Security Team
"""

print("=" * 60)
print("SMOKE TEST: patterns.py (detect-secrets + regex)")
print("=" * 60)
from patterns import run_regex_scan
regex_findings = run_regex_scan(TEST_TEXT)
print(f"  → {len(regex_findings)} finding(s) from regex/detect-secrets layer")
for f in regex_findings[:5]:
    print(f"    [{f['risk_tier']:8}] {f['credential_type']:30} | sublayer: {f.get('sublayer','?')} | {f['redacted_value']}")
if len(regex_findings) > 5:
    print(f"    ... and {len(regex_findings)-5} more")

print()
print("=" * 60)
print("SMOKE TEST: ner_detector.py (BERT / NLTK fallback)")
print("=" * 60)
from ner_detector import run_ner_scan, _get_bert_pipeline
pipe = _get_bert_pipeline()
print(f"  BERT pipeline: {'LOADED' if pipe else 'not available (NLTK fallback)'}")
ner_findings = run_ner_scan(TEST_TEXT)
print(f"  → {len(ner_findings)} finding(s) from NER layer")
for f in ner_findings[:5]:
    print(f"    [{f['risk_tier']:8}] {f['credential_type']:30} | sublayer: {f.get('sublayer','?')} | {f['redacted_value']}")
if len(ner_findings) > 5:
    print(f"    ... and {len(ner_findings)-5} more")

print()
print("=" * 60)
print("SMOKE TEST: deduplication across layers")
print("=" * 60)
from context_analyzer import deduplicate
all_raw = regex_findings + ner_findings
deduped = deduplicate(all_raw)
print(f"  Raw total: {len(all_raw)}  →  After dedup: {len(deduped)}")
multi = [f for f in deduped if len(f.get('detected_by', [])) > 1]
print(f"  Multi-layer confirmed: {len(multi)}")
for f in multi[:3]:
    print(f"    {f['credential_type']} | detected_by: {f['detected_by']}")
print()
print("ALL SMOKE TESTS COMPLETE ✓")
