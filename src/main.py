import re
import json
from typing import Dict, List, Any

class RegexExtractor:
    MALICIOUS = [
        r'<script', r'javascript:', r'onload=', r'DROP\s+TABLE',
        r'OR\s+1\s*=\s*1', r'--', r';', r'\$\{', r'whoami'
    ]
    
    EMAILS = {
       'general': r'\b[A-Za-z0-9][A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
       'alu': r'\b[A-Za-z0-9][A-Za-z0-9._%+-]+@alueducation\.com\b',
       'alumni': r'\b[A-Za-z0-9][A-Za-z0-9._%+-]+@alumni\.alueducation\.com\b',
       'si': r'\b[A-Za-z0-9][A-Za-z0-9._%+-]+@si\.alueducation\.com\b'
    }

    URL = r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[a-zA-Z0-9./?-]*)?'

    PHONE = r"\b(?:\+[0-9]{1,3}|0)[-.\s]?[0-9]{2,4}[-.\s]?[0-9]{3,4}[-.\s]?[0-9]{3,4}\b"

    CARDS = {
        'visa': r'\b4[0-9]{3}[-.\s]?[0-9]{4}[-.\s]?[0-9]{4}[-.\s]?[0-9]{4}\b',
        'mastercard': r'\b5[1-5][0-9]{2}[-.\s]?[0-9]{4}[-.\s]?[0-9]{4}[-.\s]?[0-9]{4}\b',
        'amex': r'\b3[47][0-9]{2}[-.\s]?[0-9]{6}[-.\s]?[0-9]{5}\b'
    }
    
    def __init__(self):
        self.malicious_re = [re.compile(p, re.IGNORECASE) for p in self.MALICIOUS]
   
    def is_malicious(self, text: str) -> bool:
        return any(p.search(text) for p in self.malicious_re)

    def extract_emails(self, text: str) -> Dict:
        result = {'alu_official': [], 'alumni': [], 'si': [], 'other': [], 'rejected': []}

        for email in re.findall(self.EMAILS['general'], text, re.IGNORECASE):
            if self.is_malicious(email):
                result['rejected'].append(email)
            elif re.match(self.EMAILS['alu'], email, re.IGNORECASE):
                result['alu_official'].append(email)
            elif re.match(self.EMAILS['alumni'], email, re.IGNORECASE):
                result['alumni'].append(email)
            elif re.match(self.EMAILS['si'], email, re.IGNORECASE):
                 result['si'].append(email)
            else:
                result['other'].append(email)
        return result
    
    def extract_urls(self, text: str) -> List:
        return [u for u in re.findall(self.URL, text) if not self.is_malicious(u)]

    def extract_phones(self, text: str) -> List:
        valid = []
        for p in re.findall(self.PHONE, text):
            if not self.is_malicious(p) and not re.match(r"\b[0-9]{4}[-.\s]?[0-9]{4}[-.\s]?[0-9]{4}[-.\s]?[0-9]{4}\b", p):
                digits = re.sub(r'\D', '', p)
                if 8 <= len(digits) <= 15:
                    valid.append(p.strip())
        return valid
    
    def extract_cards(self, text: str) -> List:
        cards = []
        for card_type, pattern in self.CARDS.items():
            for card in re.findall(pattern,text):
                if not self.is_malicious(card):
                    clean = re.sub(r'[-.\s]', '', card)
                    cards.append({
                        'type': card_type.upper(),
                        'masked': f'****-****-****-{clean[-4:]}',
                        'last4': clean[-4:]
                    })
        return cards

    def process(self, filepath: str) -> Dict:
        with open(filepath, 'r') as f:
            data = f.read()

        if self.is_malicious(data):
            print("[SECURITY WARNING] The malicious pattern was detected in the input")
             
        return {
            'metadata': {
                'input_file': filepath,
                'total_characters': len(data),
                'security_scan': 'completed'
            },
            'extracted_data': {
                'emails': self.extract_emails(data),
                'urls': self.extract_urls(data),
                'phones': self.extract_phones(data),
                'cards': self.extract_cards(data)
            }
        }
if __name__ == "__main__":
    extractor = RegexExtractor()
    results = extractor.process("../input/raw-text.txt")
    
    with open("../output/sample-output.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print("\n" + "="*60)
    print("ALU REGEX EXTRACTION RESULTS")
    print("="*60)
    emails = results["extracted_data"]["emails"]
    print("\n📧 EMAILS:")
    print(f"   ALU Official: {emails["alu_official"]}")
    print(f"   ALU Alumni: {emails["alumni"]}")
    print(f"   ALU SI: {emails["si"]}")
    print(f"   Other: {emails["other"]}")
    if emails["rejected"]:
        print(f"   [REJECTED]: {emails["rejected"]}")
    print(f"\n🔗 URLS ({len(results["extracted_data"]["urls"])} total):")
    for url in results["extracted_data"]["urls"]:
        print(f"   {url}")
    print(f"\n📞 PHONE NUMBERS ({len(results["extracted_data"]["phones"])} total):")
    for phone in results["extracted_data"]["phones"]:
        print(f"   {phone}")
    print(f"\n💳 CREDIT CARDS ({len(results["extracted_data"]["cards"])} total):")
    for card in results["extracted_data"]["cards"]:
        print(f"   {card["type"]}: {card["masked"]}")
    print("\n" + "="*60)
    print("✅ Output saved to: ../output/sample-output.json")
    print("🔒 Security: Malicious patterns rejected | Card numbers masked")
    print("="*60)
