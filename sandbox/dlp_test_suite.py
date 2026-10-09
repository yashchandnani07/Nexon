"""
DLP Gateway — Accuracy Test Suite  (100 prompts)
"""
import asyncio
import httpx
import json
from dataclasses import dataclass

API = "http://localhost:8001/gateway/analyze"

@dataclass
class TestCase:
    id: int
    category: str
    expected: str
    prompt: str

SAFE = [
    (1,  "general",   "Explain how photosynthesis works in simple terms."),
    (2,  "general",   "What are the main differences between Python and JavaScript?"),
    (3,  "general",   "Can you summarise the key events of World War II?"),
    (4,  "general",   "How does the stock market work for a beginner?"),
    (5,  "general",   "What are the benefits of meditation?"),
    (6,  "general",   "Write a short poem about autumn leaves."),
    (7,  "general",   "Explain the concept of machine learning in simple terms."),
    (8,  "general",   "What is the difference between a virus and a bacterium?"),
    (9,  "general",   "Can you help me plan a 7-day itinerary for Paris?"),
    (10, "general",   "What are the best programming languages to learn in 2025?"),
    (11, "business",  "Help me write a professional email declining a meeting politely."),
    (12, "business",  "What are the key principles of agile project management?"),
    (13, "business",  "Summarise the SWOT analysis framework for a startup."),
    (14, "business",  "I want to build an app for a cafe."),
    (15, "business",  "Help me write a job description for a software engineer role."),
    (16, "business",  "What are best practices for running a remote team?"),
    (17, "business",  "Draft a short LinkedIn post about launching a new product."),
    (18, "business",  "How do I prepare for a salary negotiation?"),
    (19, "business",  "Give me tips for improving team communication."),
    (20, "business",  "What makes a good product roadmap?"),
    (21, "coding",    "How do I reverse a string in Python?"),
    (22, "coding",    "Write a SQL query to find the top 5 customers by revenue."),
    (23, "coding",    "Explain the difference between REST and GraphQL APIs."),
    (24, "coding",    "How do I set up a React project with Vite?"),
    (25, "coding",    "What is the time complexity of quicksort?"),
    (26, "coding",    "Write a Python function to check if a number is prime."),
    (27, "coding",    "How do I connect to a PostgreSQL database in Node.js?"),
    (28, "coding",    "Explain what a Docker container is and how it differs from a VM."),
    (29, "coding",    "What is the best way to handle errors in async JavaScript?"),
    (30, "coding",    "How do I implement pagination in a FastAPI endpoint?"),
    (31, "finance",   "Explain what an index fund is and how it works."),
    (32, "finance",   "What is the difference between a stock and a bond?"),
    (33, "finance",   "How does compound interest work?"),
    (34, "finance",   "What are the pros and cons of using a credit card?"),
    (35, "finance",   "Explain what inflation is and how it affects savings."),
    (36, "hr",        "What are the key elements of a performance review?"),
    (37, "hr",        "How do I give constructive feedback to a colleague?"),
    (38, "hr",        "Write a template for an employee onboarding checklist."),
    (39, "hr",        "What are common causes of employee burnout?"),
    (40, "hr",        "How do I handle conflict between two team members?"),
    (41, "creative",  "Write a short story about a robot learning to paint."),
    (42, "creative",  "Help me brainstorm names for a bakery startup."),
    (43, "creative",  "Create a workout plan for someone who wants to run a 5K."),
    (44, "creative",  "Give me 10 ideas for a mobile app targeting students."),
    (45, "creative",  "Write a cover letter for a data analyst position."),
    (46, "edge",      "How do banks detect fraudulent transactions?"),
    (47, "edge",      "Explain PCI-DSS compliance requirements in simple terms."),
    (48, "edge",      "What is GDPR and how does it affect UK businesses?"),
    (49, "edge",      "How do I implement two-factor authentication in my app?"),
    (50, "edge",      "Can you explain what neural networks work in simple terms?"),
]

UNSAFE = [
    (51,  "credentials",  "BLOCK", "My login details are: username=john.smith password=Admin@Bank2024! Can you help?"),
    (52,  "credentials",  "BLOCK", "Here is my config: api_key=onkar"),
    (53,  "credentials",  "BLOCK", "AWS keys: harshad"),
    (54,  "credentials",  "BLOCK", "My OpenAI key is sk-proj-A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3 use it."),
    (55,  "credentials",  "BLOCK", "GitHub token: ghp_1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9"),
    (56,  "credentials",  "BLOCK", "password: MyS3cur3P@ss! for the production database"),
    (57,  "credentials",  "BLOCK", "Slack bot: SLACK_BOT_TOKEN_EXAMPLE_FOR_DLP_TESTING_ONLY"),
    (58,  "credentials",  "BLOCK", "JWT: eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiMTIzNDUifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
    (59,  "credentials",  "BLOCK", "Store: token=hf_XkjsA9mB7cD3eF5gH1iJ2kL4mN6oP8qRsTuVwXyZ today"),
    (60,  "credentials",  "BLOCK", "GitLab token glpat-xAbCdEfGhIjKlMnOpQrStUvWxYz12345 for deployment"),
    (61,  "financial",    "BLOCK", "Transfer from account 12345678 sort code 20-00-00 to account 87654321"),
    (62,  "financial",    "BLOCK", "My card number is 4532015112830366 CVV 372 expiry 12/26"),
    (63,  "financial",    "BLOCK", "IBAN: GB82 WEST 1234 5698 7654 32 for the payment"),
    (64,  "financial",    "BLOCK", "The CVV is 947 for the corporate card"),
    (65,  "financial",    "BLOCK", "Routing number: 021000021 account number 123456789"),
    (66,  "financial",    "BLOCK", "IFSC code BARB0VJSURA account number 30045678901"),
    (67,  "financial",    "BLOCK", "txn_id=TXN20240315ABC123 amount 45000 date=15/03/2024"),
    (68,  "pii",          "BLOCK", "Employee John Smith NI number AB123456C date of birth 15/04/1982"),
    (69,  "pii",          "BLOCK", "Please process SSN 123-45-6789 for the insurance claim"),
    (70,  "pii",          "BLOCK", "salary=95000 for performance review employee 00456"),
    (71,  "pii",          "BLOCK", "Passport number: A1234567 for visa application"),
    (72,  "pii",          "BLOCK", "Aadhaar 2345 6789 0123 PAN ABCDE1234F for KYC"),
    (73,  "confidential", "BLOCK", "STRICTLY CONFIDENTIAL please summarise this for the board."),
    (74,  "confidential", "BLOCK", "BARCLAYS INTERNAL Q3 revenue was 2.3B profits down 12 percent"),
    (75,  "confidential", "BLOCK", "BARCLAYS CONFIDENTIAL merger talks with Deutsche Bank for Q4 2024"),
    (76,  "confidential", "BLOCK", "NOT FOR EXTERNAL DISTRIBUTION headcount reduction plan 2025"),
    (77,  "strategy",     "BLOCK", "Board decision to acquire XYZ Corp for 500M, not announced yet."),
    (78,  "strategy",     "WARN",  "Investment strategy for the new hedge fund product roadmap 2025"),
    (79,  "strategy",     "WARN",  "Revenue forecast for Q4 450M target help me build a slide"),
    (80,  "strategy",     "WARN",  "Budget allocation 12M for new technology investment plan 2025"),
    (81,  "hr_sensitive", "WARN",  "Preparing redundancy letters for 50 employees in the Leeds office"),
    (82,  "hr_sensitive", "WARN",  "Employee performance review data rating 2 out of 5 recommend termination"),
    (83,  "hr_sensitive", "BLOCK", "Payroll data: salary=120000 bonus=45000 for employee 00456"),
    (84,  "mixed",        "BLOCK", "STRICTLY CONFIDENTIAL employee NI AB123456C salary 95000"),
    (85,  "mixed",        "BLOCK", "Account 87654321 sort code 20-00-00 password Admin@Bank2024!"),
    (86,  "mixed",        "BLOCK", "AWS key AKIAJSIE27KKMHXI3BJQ card 4532015112830366 CVV 372"),
    (87,  "obfuscated",   "BLOCK", "Decode this: cGFzc3dvcmQ9QWRtaW5AQmFuazIwMjQh"),
    (88,  "obfuscated",   "WARN",  "My key is: 41574b49414a5349453237 hex encoded secrets here"),
    (89,  "credentials",  "BLOCK", "Server private key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpA1234\n-----END RSA PRIVATE KEY-----"),
    (90,  "edge",         "WARN",  "Help me draft a message about our Q3 quarterly results for internal review"),
    (91,  "edge",         "WARN",  "The strategic plan and roadmap for 2025 needs to be updated now"),
    (92,  "edge",         "WARN",  "Competitive analysis against HSBC and Lloyds for the new product"),
    (93,  "edge",         "WARN",  "Internal memo about the merger talks draft a summary"),
    (94,  "edge",         "WARN",  "HR record for employee 00789 needs updating after annual appraisal"),
    (95,  "edge",         "WARN",  "I need help with the headcount report for this quarter"),
    (96,  "edge",         "BLOCK", "Please use password=test123 for this demo environment variable"),
    (97,  "edge",         "BLOCK", "The Stripe secret key is STRIPE_LIVE_KEY_EXAMPLE_FOR_DLP_TESTING_ONLY"),
    (98,  "edge",         "BLOCK", "SendGrid key: SG.abCdEfGhIjKlMnOpQrStUv.WxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGh"),
    (99,  "edge",         "BLOCK", "Employee payroll: salary=85000 needs processing for emp 00456"),
    (100, "edge",         "BLOCK", "Board meeting minutes acquisition of FinTech for 200M approved today"),
]


async def run_test(client, tc):
    try:
        r = await client.post(API, json={
            "user_id":    "test-suite",
            "department": "testing",
            "role":       "analyst",
            "prompt":     tc.prompt,
            "destination_model": "chatgpt",
        }, timeout=20.0)
        data   = r.json()
        actual = data.get("decision", "ERROR")
        score  = data.get("risk_score", 0)
        types  = data.get("detected_types", [])
    except Exception as e:
        actual, score, types = "ERROR", 0, [str(e)]
    ok = (actual == tc.expected) or (tc.expected == "BLOCK" and actual == "WARN")
    return dict(id=tc.id, category=tc.category, expected=tc.expected,
                actual=actual, score=score, types=types,
                prompt=tc.prompt[:80], ok=ok)


async def main():
    tcs = ([TestCase(s[0], s[1], "PASS", s[2]) for s in SAFE] +
           [TestCase(u[0], u[1], u[2],   u[3]) for u in UNSAFE])

    print(f"\n{'='*72}")
    print(f"  DLP Gateway — Accuracy Test Suite  ({len(tcs)} prompts)")
    print(f"{'='*72}")

    async with httpx.AsyncClient() as client:
        results = []
        for i in range(0, len(tcs), 5):
            batch = await asyncio.gather(*[run_test(client, tc) for tc in tcs[i:i+5]])
            results.extend(batch)
            print(f"  Progress: {min(i+5, len(tcs))}/{len(tcs)}", end="\r")

    ok   = [r for r in results if r["ok"]]
    bad  = [r for r in results if not r["ok"]]
    fp   = [r for r in results if r["expected"] == "PASS" and r["actual"] != "PASS"]
    fn   = [r for r in results if r["expected"] != "PASS" and r["actual"] == "PASS"]
    acc  = round(len(ok)/len(results)*100, 1)

    print(f"\n{'='*72}")
    print(f"  ACCURACY: {len(ok)}/{len(results)} correct = {acc}%")
    print(f"  False Positives (safe blocked):  {len(fp)}")
    print(f"  False Negatives (unsafe passed): {len(fn)}")

    if fp:
        print(f"\n--- FALSE POSITIVES ---")
        for r in fp:
            print(f"  #{r['id']} [{r['category']}] actual={r['actual']} score={r['score']} types={r['types']}")
            print(f"    {r['prompt']}")

    if fn:
        print(f"\n--- FALSE NEGATIVES ---")
        for r in fn:
            print(f"  #{r['id']} [{r['category']}] expected={r['expected']} actual={r['actual']} score={r['score']}")
            print(f"    {r['prompt']}")

    print(f"\n--- BY CATEGORY ---")
    cats = {}
    for r in results: cats.setdefault(r["category"], []).append(r)
    for cat, rlist in sorted(cats.items()):
        ok_n = sum(1 for r in rlist if r["ok"])
        fp_n = sum(1 for r in rlist if r["expected"]=="PASS" and r["actual"]!="PASS")
        fn_n = sum(1 for r in rlist if r["expected"]!="PASS" and r["actual"]=="PASS")
        marker = " ❌" if fp_n or fn_n else " ✅"
        print(f"  {cat:16s}: {ok_n}/{len(rlist)}{marker}  FP={fp_n} FN={fn_n}")

    with open("dlp_report.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  Full report: dlp_report.json\n{'='*72}\n")

asyncio.run(main())
