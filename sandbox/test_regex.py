import re

cases = [
    ("SSN", r"\b\d{3}-\d{2}-\d{4}\b",
     "Please process SSN 123-45-6789 for the insurance claim"),
    ("IBAN", r"\b[A-Z]{2}[0-9]{2}(?:\s?[A-Z0-9]{4}){4,9}\b",
     "IBAN: GB82 WEST 1234 5698 7654 32 for the payment"),
    ("CVV", r"(?i)(?:cvv|cvc)\s+(?:is|was)\s+(\d{3,4})",
     "The CVV is 947 for the corporate card"),
    ("salary", r"(?i)salary\s*=\s*[\d,]{4,}",
     "salary=95000 for performance review employee 00456"),
    ("passport", r"(?i)passport\s+number[:\s]+[A-Z]\d{7}",
     "Passport number: A1234567 for visa application"),
    ("password_short", r"(?i)password\s*=\s*\S{4,}",
     "Please use password=test123 for this demo environment variable"),
    ("Aadhaar", r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b",
     "Aadhaar 2345 6789 0123 PAN ABCDE1234F for KYC"),
    ("PAN", r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
     "Aadhaar 2345 6789 0123 PAN ABCDE1234F for KYC"),
]
for name, pat, txt in cases:
    m = re.search(pat, txt)
    print(f"{name}: {'MATCH' if m else 'NO MATCH'}  -> {m.group() if m else '-'}")
