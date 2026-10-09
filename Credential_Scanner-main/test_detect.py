from detect_secrets.plugins.base import RegexBasedDetector
import re

class MyScanner(RegexBasedDetector):
    secret_type = "MySecret"
    
    def __init__(self):
        self.secret_regex = re.compile(r"password is (\w+)")
        super().__init__()
        
d = MyScanner()
print(list(d.analyze_string("my password is secret", 1, "test.txt")))
