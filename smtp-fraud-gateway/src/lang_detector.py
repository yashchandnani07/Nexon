"""
Language Detector & Multilingual Phishing Patterns
====================================================
Per-sentence language detection using langdetect.
Identifies mixed-language emails (code-switching) as social engineering signal.
Includes phishing lexicons for Hindi, Spanish, French, German.
"""

import re
from typing import List, Dict

# Try langdetect first, fall back to simple heuristics
try:
    from langdetect import detect as _detect_lang, detect_langs as _detect_probs
    from langdetect import LangDetectException
    HAS_LANGDETECT = True
except ImportError:
    HAS_LANGDETECT = False

# ── Sentence splitter ────────────────────────────────────────────────────────
SENT_RE = re.compile(r'[.!?।\n]+')

# ── Multilingual phishing lexicons ───────────────────────────────────────────
# Weighted patterns: (regex_pattern, weight, description)

PHISHING_LEXICONS = {
    "hi": [  # Hindi / Hinglish
        (re.compile(r'अगर\s.*नहीं\s.*किया', re.IGNORECASE), 0.3, "Conditional threat (Hindi)"),
        (re.compile(r'कृपया.*(?:upload|verify|confirm)', re.IGNORECASE), 0.4, "Polite phishing request (Hindi)"),
        (re.compile(r'KYC.*document|document.*KYC', re.IGNORECASE), 0.3, "KYC lure"),
        (re.compile(r'OTP|one.time.password', re.IGNORECASE), 0.3, "OTP reference"),
        (re.compile(r'Aadhaar|aadhaar|आधार', re.IGNORECASE), 0.2, "Aadhaar reference"),
        (re.compile(r'आप\s.*चाहें\s.*तो|check\s.*कर\s.*सकते', re.IGNORECASE), 0.2, "Soft push (Hindi)"),
        (re.compile(r'तुरंत', re.IGNORECASE), 0.2, "Urgency (Hindi)"),
        (re.compile(r'pending.*verification|verification.*pending', re.IGNORECASE), 0.3, "Pending verification lure"),
    ],
    "es": [  # Spanish
        (re.compile(r'Estimado\s+cliente', re.IGNORECASE), 0.2, "Formal greeting (Spanish)"),
        (re.compile(r'urgente|inmediatamente', re.IGNORECASE), 0.3, "Urgency (Spanish)"),
        (re.compile(r'Adjunto|adjunto', re.IGNORECASE), 0.2, "Attachment reference (Spanish)"),
        (re.compile(r'verificar\s.*cuenta|cuenta\s.*verificar', re.IGNORECASE), 0.4, "Account verify (Spanish)"),
        (re.compile(r'suspender|suspendido|bloqueado', re.IGNORECASE), 0.3, "Account suspension (Spanish)"),
    ],
    "fr": [  # French
        (re.compile(r'tentative\s+de\s+connexion', re.IGNORECASE), 0.3, "Login attempt (French)"),
        (re.compile(r'Bonjour.*détectée|détectée.*Bonjour', re.IGNORECASE), 0.3, "Detection alert (French)"),
        (re.compile(r'vérifier|confirmer.*identité', re.IGNORECASE), 0.3, "Verify identity (French)"),
        (re.compile(r'Sécurité|sécurité', re.IGNORECASE), 0.2, "Security reference (French)"),
        (re.compile(r'immédiatement|urgent', re.IGNORECASE), 0.3, "Urgency (French)"),
    ],
    "de": [  # German
        (re.compile(r'Bitte\s+prüfen', re.IGNORECASE), 0.3, "Please check (German)"),
        (re.compile(r'Sicherheit|Sicherheits', re.IGNORECASE), 0.2, "Security reference (German)"),
        (re.compile(r'sofort|dringend|umgehend', re.IGNORECASE), 0.3, "Urgency (German)"),
        (re.compile(r'Bestätigung|bestätigen', re.IGNORECASE), 0.3, "Confirmation request (German)"),
        (re.compile(r'Angaben|Überprüfung', re.IGNORECASE), 0.2, "Details/Review (German)"),
        (re.compile(r'Ihr\s+Konto\s+(?:wurde|ist|wird)\s+(?:gesperrt|deaktiviert|blockiert)', re.IGNORECASE), 0.5, "Account blocked (German)"),
        (re.compile(r'Klicken\s+Sie\s+hier|Jetzt\s+verifizieren', re.IGNORECASE), 0.4, "Click here / verify now (German)"),
    ],
    "ar": [  # Arabic — major phishing target region
        (re.compile(r'عاجل|فوري', re.IGNORECASE), 0.3, "Urgency (Arabic)"),
        (re.compile(r'تحقق\s+من\s+حسابك|التحقق\s+من\s+الهوية', re.IGNORECASE), 0.4, "Verify account/identity (Arabic)"),
        (re.compile(r'تعليق\s+الحساب|تم\s+تعليق|حسابك\s+معلق', re.IGNORECASE), 0.5, "Account suspension (Arabic)"),
        (re.compile(r'انقر\s+هنا|اضغط\s+هنا', re.IGNORECASE), 0.4, "Click here (Arabic)"),
        (re.compile(r'كلمة\s+المرور|بيانات\s+الدخول', re.IGNORECASE), 0.3, "Password / login data (Arabic)"),
        (re.compile(r'البنك|حسابك\s+المصرفي', re.IGNORECASE), 0.2, "Banking reference (Arabic)"),
        (re.compile(r'OTP|رمز\s+التحقق', re.IGNORECASE), 0.3, "OTP reference (Arabic)"),
    ],
    "pt": [  # Portuguese — Brazil is #1 phishing target globally
        (re.compile(r'Caro\s+cliente|Prezado\s+(?:cliente|usuário)', re.IGNORECASE), 0.2, "Dear customer (Portuguese)"),
        (re.compile(r'urgente|imediatamente', re.IGNORECASE), 0.3, "Urgency (Portuguese)"),
        (re.compile(r'verificar?\s+(?:sua\s+)?conta|conta\s+verificar?', re.IGNORECASE), 0.4, "Verify account (Portuguese)"),
        (re.compile(r'sua\s+conta\s+(?:foi\s+)?(?:suspensa|bloqueada|desativada)', re.IGNORECASE), 0.5, "Account suspended (Portuguese)"),
        (re.compile(r'clique\s+aqui|acesse\s+agora', re.IGNORECASE), 0.4, "Click here (Portuguese)"),
        (re.compile(r'confirme?\s+(?:seus\s+)?dados|atualiz(?:e|ar)\s+(?:suas\s+)?informações', re.IGNORECASE), 0.4, "Confirm/update data (Portuguese)"),
        (re.compile(r'senha|CPF|cartão\s+de\s+crédito', re.IGNORECASE), 0.3, "Password/CPF/credit card (Portuguese)"),
    ],
    "it": [  # Italian
        (re.compile(r'Gentile\s+cliente|Caro\s+(?:cliente|utente)', re.IGNORECASE), 0.2, "Dear customer (Italian)"),
        (re.compile(r'urgente|immediatamente', re.IGNORECASE), 0.3, "Urgency (Italian)"),
        (re.compile(r'verifica(?:re)?\s+(?:il\s+tuo\s+)?account|account\s+verifica', re.IGNORECASE), 0.4, "Verify account (Italian)"),
        (re.compile(r'(?:il\s+tuo\s+)?account\s+è\s+stato\s+sospeso|account\s+bloccato', re.IGNORECASE), 0.5, "Account suspended (Italian)"),
        (re.compile(r'clicca\s+qui|accedi\s+ora', re.IGNORECASE), 0.4, "Click here (Italian)"),
        (re.compile(r'conferma(?:re)?\s+(?:i\s+tuoi\s+)?dati|aggiorna(?:re)?\s+(?:le\s+tue\s+)?informazioni', re.IGNORECASE), 0.4, "Confirm/update data (Italian)"),
        (re.compile(r'codice\s+(?:OTP|di\s+sicurezza)|la\s+tua\s+password', re.IGNORECASE), 0.3, "OTP/password (Italian — with Italian context)"),
    ],
    "ru": [  # Russian — significant phishing activity
        (re.compile(r'Уважаемый\s+клиент|Уважаемый\s+пользователь', re.IGNORECASE), 0.2, "Dear customer (Russian)"),
        (re.compile(r'срочно|немедленно', re.IGNORECASE), 0.3, "Urgency (Russian)"),
        (re.compile(r'подтвердить\s+(?:ваш\s+)?аккаунт|верификация\s+аккаунта', re.IGNORECASE), 0.4, "Verify account (Russian)"),
        (re.compile(r'ваш\s+аккаунт\s+(?:заблокирован|приостановлен|заморожен)', re.IGNORECASE), 0.5, "Account blocked (Russian)"),
        (re.compile(r'нажмите\s+здесь|перейдите\s+по\s+ссылке', re.IGNORECASE), 0.4, "Click here / follow link (Russian)"),
        (re.compile(r'пароль|логин|данные\s+(?:входа|карты)', re.IGNORECASE), 0.3, "Password/login/card data (Russian)"),
        (re.compile(r'банк|перевод\s+средств', re.IGNORECASE), 0.2, "Bank/transfer (Russian)"),
    ],
    "zh": [  # Chinese (Simplified)
        (re.compile(r'紧急|立即|马上', re.IGNORECASE), 0.3, "Urgency (Chinese)"),
        (re.compile(r'请.*验证|验证.*账户|账户.*验证', re.IGNORECASE), 0.4, "Verify account (Chinese)"),
        (re.compile(r'账户.*(?:已被)?(?:暂停|冻结|封禁)|您的账户.*异常', re.IGNORECASE), 0.5, "Account suspended/frozen (Chinese)"),
        (re.compile(r'点击此处|立即登录|点击链接', re.IGNORECASE), 0.4, "Click here / login now (Chinese)"),
        (re.compile(r'密码|登录信息|银行卡', re.IGNORECASE), 0.3, "Password/login/bank card (Chinese)"),
        (re.compile(r'一次性密码|验证码', re.IGNORECASE), 0.3, "OTP/verification code (Chinese)"),
    ],
    "ja": [  # Japanese
        (re.compile(r'緊急|至急|すぐに', re.IGNORECASE), 0.3, "Urgency (Japanese)"),
        (re.compile(r'アカウント.*確認|確認.*アカウント|本人確認', re.IGNORECASE), 0.4, "Account verification (Japanese)"),
        (re.compile(r'アカウント.*(?:停止|凍結|ロック)|ご利用.*停止', re.IGNORECASE), 0.5, "Account suspended (Japanese)"),
        (re.compile(r'こちらをクリック|ログインはこちら|今すぐ確認', re.IGNORECASE), 0.4, "Click here / verify now (Japanese)"),
        (re.compile(r'パスワード|暗証番号|クレジットカード', re.IGNORECASE), 0.3, "Password/PIN/credit card (Japanese)"),
        (re.compile(r'ワンタイムパスワード|認証コード', re.IGNORECASE), 0.3, "OTP/auth code (Japanese)"),
    ],
    "ko": [  # Korean
        (re.compile(r'긴급|즉시|빨리', re.IGNORECASE), 0.3, "Urgency (Korean)"),
        (re.compile(r'계정.*확인|본인.*인증|계정.*인증', re.IGNORECASE), 0.4, "Account verification (Korean)"),
        (re.compile(r'계정.*(?:정지|잠금|차단|일시중지)|서비스.*이용.*불가', re.IGNORECASE), 0.5, "Account suspended (Korean)"),
        (re.compile(r'여기.*클릭|지금.*로그인|확인하기', re.IGNORECASE), 0.4, "Click here / login now (Korean)"),
        (re.compile(r'비밀번호|개인정보|신용카드', re.IGNORECASE), 0.3, "Password/personal info/credit card (Korean)"),
        (re.compile(r'일회용\s*비밀번호|인증\s*번호', re.IGNORECASE), 0.3, "OTP/auth code (Korean)"),
    ],
    "tr": [  # Turkish
        (re.compile(r'Sayın\s+(?:müşteri|kullanıcı)', re.IGNORECASE), 0.2, "Dear customer (Turkish)"),
        (re.compile(r'acil|hemen|derhal', re.IGNORECASE), 0.3, "Urgency (Turkish)"),
        (re.compile(r'hesabınızı\s+doğrulayın|doğrulama\s+gerekli', re.IGNORECASE), 0.4, "Verify account (Turkish)"),
        (re.compile(r'hesabınız\s+(?:askıya\s+alınmıştır|bloke\s+edilmiştir|dondurulmuştur)', re.IGNORECASE), 0.5, "Account suspended (Turkish)"),
        (re.compile(r'buraya\s+tıklayın|hemen\s+giriş\s+yapın', re.IGNORECASE), 0.4, "Click here / login now (Turkish)"),
        (re.compile(r'şifre(?:nizi)?|parola|banka\s+bilgileri', re.IGNORECASE), 0.3, "Password/bank info (Turkish)"),
    ],
    "nl": [  # Dutch — important for EU banking phishing
        (re.compile(r'Geachte\s+klant|Beste\s+(?:klant|gebruiker)', re.IGNORECASE), 0.2, "Dear customer (Dutch)"),
        (re.compile(r'dringend|onmiddellijk', re.IGNORECASE), 0.3, "Urgency (Dutch)"),
        (re.compile(r'verifieer\s+(?:uw\s+)?account|account\s+verifi', re.IGNORECASE), 0.4, "Verify account (Dutch)"),
        (re.compile(r'uw\s+account\s+(?:is|werd)\s+(?:geblokkeerd|opgeschort|bevroren)', re.IGNORECASE), 0.5, "Account blocked (Dutch)"),
        (re.compile(r'klik\s+hier|nu\s+inloggen', re.IGNORECASE), 0.4, "Click here / login now (Dutch)"),
        (re.compile(r'wachtwoord|inloggegevens|bankpas', re.IGNORECASE), 0.3, "Password/login/bankcard (Dutch)"),
    ],
    # ── Indian Regional Languages ─────────────────────────────────────────────
    "mr": [  # Marathi — Maharashtra, major banking/fintech hub
        (re.compile(r'तुमचे\s+खाते\s+(?:बंद|निलंबित|ब्लॉक)\s+केले', re.IGNORECASE), 0.5, "Account suspended (Marathi)"),
        (re.compile(r'कृपया.*(?:सत्यापित|verify|confirm)\s+करा', re.IGNORECASE), 0.4, "Please verify (Marathi)"),
        (re.compile(r'तातडीने|लगेच|त्वरित', re.IGNORECASE), 0.3, "Urgency (Marathi)"),
        (re.compile(r'OTP|एक-वेळ\s+पासवर्ड', re.IGNORECASE), 0.3, "OTP reference (Marathi)"),
        (re.compile(r'येथे\s+क्लिक\s+करा|लिंकवर\s+क्लिक', re.IGNORECASE), 0.4, "Click here (Marathi)"),
        (re.compile(r'आधार|पॅन\s+कार्ड|बँक\s+खाते', re.IGNORECASE), 0.3, "Aadhaar/PAN/bank account (Marathi)"),
        (re.compile(r'पासवर्ड|गुप्त\s+शब्द', re.IGNORECASE), 0.3, "Password (Marathi)"),
        (re.compile(r'KYC.*(?:अपडेट|पूर्ण)|(?:अपडेट|पूर्ण).*KYC', re.IGNORECASE), 0.4, "KYC update (Marathi)"),
    ],
    "bn": [  # Bengali — West Bengal + Bangladesh
        (re.compile(r'আপনার\s+(?:অ্যাকাউন্ট|একাউন্ট)\s+(?:স্থগিত|বন্ধ|ব্লক)', re.IGNORECASE), 0.5, "Account suspended (Bengali)"),
        (re.compile(r'অনুগ্রহ\s+করে.*(?:যাচাই|নিশ্চিত)\s+করুন', re.IGNORECASE), 0.4, "Please verify (Bengali)"),
        (re.compile(r'জরুরি|এখনই|তাৎক্ষণিক', re.IGNORECASE), 0.3, "Urgency (Bengali)"),
        (re.compile(r'OTP|এককালীন\s+পাসওয়ার্ড', re.IGNORECASE), 0.3, "OTP reference (Bengali)"),
        (re.compile(r'এখানে\s+ক্লিক|লিঙ্কে\s+ক্লিক', re.IGNORECASE), 0.4, "Click here (Bengali)"),
        (re.compile(r'আধার|প্যান\s+কার্ড|ব্যাংক\s+অ্যাকাউন্ট', re.IGNORECASE), 0.3, "Aadhaar/PAN/bank (Bengali)"),
        (re.compile(r'পাসওয়ার্ড|গোপন\s+নম্বর', re.IGNORECASE), 0.3, "Password/PIN (Bengali)"),
        (re.compile(r'KYC.*আপডেট|আপডেট.*KYC', re.IGNORECASE), 0.4, "KYC update (Bengali)"),
    ],
    "ta": [  # Tamil — Tamil Nadu + Sri Lanka
        (re.compile(r'உங்கள்\s+கணக்கு\s+(?:நிறுத்தப்பட்டது|தடுக்கப்பட்டது|முடக்கப்பட்டது)', re.IGNORECASE), 0.5, "Account suspended (Tamil)"),
        (re.compile(r'தயவுசெய்து.*(?:சரிபார்க்கவும்|உறுதிப்படுத்தவும்)', re.IGNORECASE), 0.4, "Please verify (Tamil)"),
        (re.compile(r'அவசரம்|உடனடியாக|இப்போதே', re.IGNORECASE), 0.3, "Urgency (Tamil)"),
        (re.compile(r'OTP|ஒருமுறை\s+கடவுச்சொல்', re.IGNORECASE), 0.3, "OTP reference (Tamil)"),
        (re.compile(r'இங்கே\s+கிளிக்|இணைப்பை\s+கிளிக்', re.IGNORECASE), 0.4, "Click here (Tamil)"),
        (re.compile(r'ஆதார்|பான்\s+கார்டு|வங்கி\s+கணக்கு', re.IGNORECASE), 0.3, "Aadhaar/PAN/bank (Tamil)"),
        (re.compile(r'கடவுச்சொல்|இரகசிய\s+எண்', re.IGNORECASE), 0.3, "Password/PIN (Tamil)"),
        (re.compile(r'KYC.*புதுப்பிக்க|புதுப்பிக்க.*KYC', re.IGNORECASE), 0.4, "KYC update (Tamil)"),
    ],
    "te": [  # Telugu — Andhra Pradesh + Telangana
        (re.compile(r'మీ\s+ఖాతా\s+(?:నిలిపివేయబడింది|బ్లాక్\s+చేయబడింది|నిలిపివేసారు)', re.IGNORECASE), 0.5, "Account suspended (Telugu)"),
        (re.compile(r'దయచేసి.*(?:ధృవీకరించండి|నిర్ధారించండి)', re.IGNORECASE), 0.4, "Please verify (Telugu)"),
        (re.compile(r'అత్యవసరం|వెంటనే|తక్షణమే', re.IGNORECASE), 0.3, "Urgency (Telugu)"),
        (re.compile(r'OTP|వన్-టైమ్\s+పాస్వర్డ్', re.IGNORECASE), 0.3, "OTP reference (Telugu)"),
        (re.compile(r'ఇక్కడ\s+క్లిక్|లింక్\s+నొక్కండి', re.IGNORECASE), 0.4, "Click here (Telugu)"),
        (re.compile(r'ఆధార్|పాన్\s+కార్డ్|బ్యాంక్\s+ఖాతా', re.IGNORECASE), 0.3, "Aadhaar/PAN/bank (Telugu)"),
        (re.compile(r'పాస్వర్డ్|రహస్య\s+సంఖ్య', re.IGNORECASE), 0.3, "Password/PIN (Telugu)"),
    ],
    "kn": [  # Kannada — Karnataka
        (re.compile(r'ನಿಮ್ಮ\s+ಖಾತೆ\s+(?:ನಿಲ್ಲಿಸಲಾಗಿದೆ|ನಿರ್ಬಂಧಿಸಲಾಗಿದೆ|ಬ್ಲಾಕ್\s+ಆಗಿದೆ)', re.IGNORECASE), 0.5, "Account suspended (Kannada)"),
        (re.compile(r'ದಯವಿಟ್ಟು.*(?:ಪರಿಶೀಲಿಸಿ|ದೃಢೀಕರಿಸಿ)', re.IGNORECASE), 0.4, "Please verify (Kannada)"),
        (re.compile(r'ತುರ್ತು|ತಕ್ಷಣ|ಇಂದೇ', re.IGNORECASE), 0.3, "Urgency (Kannada)"),
        (re.compile(r'OTP|ಒಂದು-ಬಾರಿ\s+ಪಾಸ್ವರ್ಡ್', re.IGNORECASE), 0.3, "OTP reference (Kannada)"),
        (re.compile(r'ಇಲ್ಲಿ\s+ಕ್ಲಿಕ್\s+ಮಾಡಿ|ಲಿಂಕ್\s+ಕ್ಲಿಕ್', re.IGNORECASE), 0.4, "Click here (Kannada)"),
        (re.compile(r'ಆಧಾರ್|ಪ್ಯಾನ್\s+ಕಾರ್ಡ್|ಬ್ಯಾಂಕ್\s+ಖಾತೆ', re.IGNORECASE), 0.3, "Aadhaar/PAN/bank (Kannada)"),
        (re.compile(r'ಪಾಸ್ವರ್ಡ್|ಗುಪ್ತ\s+ಸಂಖ್ಯೆ', re.IGNORECASE), 0.3, "Password/PIN (Kannada)"),
    ],
    "ml": [  # Malayalam — Kerala
        (re.compile(r'നിങ്ങളുടെ\s+അക്കൗണ്ട്\s+(?:സസ്പെൻഡ്|ബ്ലോക്ക്)\s+ചെയ്തിരിക്കുന്നു', re.IGNORECASE), 0.5, "Account suspended (Malayalam)"),
        (re.compile(r'ദയവായി.*(?:സ്ഥിരീകരിക്കൂ|ഉറപ്പുവരുത്തൂ)', re.IGNORECASE), 0.4, "Please verify (Malayalam)"),
        (re.compile(r'അടിയന്തരം|ഉടനടി|ഉടൻ', re.IGNORECASE), 0.3, "Urgency (Malayalam)"),
        (re.compile(r'OTP|ഒറ്റ-ഉപയോഗ\s+പാസ്വേഡ്', re.IGNORECASE), 0.3, "OTP reference (Malayalam)"),
        (re.compile(r'ഇവിടെ\s+ക്ലിക്|ലിങ്കിൽ\s+ക്ലിക്', re.IGNORECASE), 0.4, "Click here (Malayalam)"),
        (re.compile(r'ആധാർ|പാൻ\s+കാർഡ്|ബാങ്ക്\s+അക്കൗണ്ട്', re.IGNORECASE), 0.3, "Aadhaar/PAN/bank (Malayalam)"),
        (re.compile(r'പാസ്വേഡ്|രഹസ്യ\s+നമ്പർ', re.IGNORECASE), 0.3, "Password/PIN (Malayalam)"),
    ],
    "gu": [  # Gujarati — Gujarat, major business/finance state
        (re.compile(r'તમારું\s+ખાતું\s+(?:સસ્પેન્ડ|બ્લૉક)\s+(?:કરવામાં\s+આવ્યું|થઈ\s+ગયું)', re.IGNORECASE), 0.5, "Account suspended (Gujarati)"),
        (re.compile(r'કૃપા\s+કરીને.*(?:ચકાસો|સ્ત્રે|verify)\s+કરો', re.IGNORECASE), 0.4, "Please verify (Gujarati)"),
        (re.compile(r'તાકીદ|તાત્કાલિક|તુરંત', re.IGNORECASE), 0.3, "Urgency (Gujarati)"),
        (re.compile(r'OTP|એક-વખત\s+પાસવર્ડ', re.IGNORECASE), 0.3, "OTP reference (Gujarati)"),
        (re.compile(r'અહીં\s+ક્લિક|લિંક\s+પર\s+ક્લિક', re.IGNORECASE), 0.4, "Click here (Gujarati)"),
        (re.compile(r'આધાર|પૅન\s+કાર્ડ|બૅંક\s+ખાતું', re.IGNORECASE), 0.3, "Aadhaar/PAN/bank (Gujarati)"),
        (re.compile(r'પાસવર્ડ|ગુપ્ત\s+નંબર', re.IGNORECASE), 0.3, "Password/PIN (Gujarati)"),
        (re.compile(r'KYC.*અપડેટ|અપડેट.*KYC', re.IGNORECASE), 0.4, "KYC update (Gujarati)"),
    ],
    "pa": [  # Punjabi (Gurmukhi script) — Punjab + diaspora
        (re.compile(r'ਤੁਹਾਡਾ\s+ਖਾਤਾ\s+(?:ਮੁਅੱਤਲ|ਬਲੌਕ)\s+(?:ਕੀਤਾ\s+ਗਿਆ|ਹੋ\s+ਗਿਆ)', re.IGNORECASE), 0.5, "Account suspended (Punjabi)"),
        (re.compile(r'ਕਿਰਪਾ\s+ਕਰਕੇ.*(?:ਤਸਦੀਕ|verify)\s+ਕਰੋ', re.IGNORECASE), 0.4, "Please verify (Punjabi)"),
        (re.compile(r'ਫ਼ੌਰੀ|ਤੁਰੰਤ|ਹੁਣੇ', re.IGNORECASE), 0.3, "Urgency (Punjabi)"),
        (re.compile(r'OTP|ਇੱਕ-ਵਾਰੀ\s+ਪਾਸਵਰਡ', re.IGNORECASE), 0.3, "OTP reference (Punjabi)"),
        (re.compile(r'ਇੱਥੇ\s+ਕਲਿੱਕ|ਲਿੰਕ\s+ਉੱਤੇ\s+ਕਲਿੱਕ', re.IGNORECASE), 0.4, "Click here (Punjabi)"),
        (re.compile(r'ਆਧਾਰ|ਪੈਨ\s+ਕਾਰਡ|ਬੈਂਕ\s+ਖਾਤਾ', re.IGNORECASE), 0.3, "Aadhaar/PAN/bank (Punjabi)"),
        (re.compile(r'ਪਾਸਵਰਡ|ਗੁਪਤ\s+ਨੰਬਰ', re.IGNORECASE), 0.3, "Password/PIN (Punjabi)"),
    ],
    "ur": [  # Urdu — uses Arabic script, major language in Pakistan + India
        (re.compile(r'آپ\s+کا\s+اکاؤنٹ\s+(?:معطل|بلاک)\s+(?:کر\s+دیا|ہو\s+گیا)', re.IGNORECASE), 0.5, "Account suspended (Urdu)"),
        (re.compile(r'براہ\s+کرم.*(?:تصدیق|verify)\s+کریں', re.IGNORECASE), 0.4, "Please verify (Urdu)"),
        (re.compile(r'فوری|فوراً|ابھی', re.IGNORECASE), 0.3, "Urgency (Urdu)"),
        (re.compile(r'OTP|یک-وقتی\s+پاس\s+ورڈ', re.IGNORECASE), 0.3, "OTP reference (Urdu)"),
        (re.compile(r'یہاں\s+کلک|لنک\s+پر\s+کلک', re.IGNORECASE), 0.4, "Click here (Urdu)"),
        (re.compile(r'آدھار|پین\s+کارڈ|بینک\s+اکاؤنٹ', re.IGNORECASE), 0.3, "Aadhaar/PAN/bank (Urdu)"),
        (re.compile(r'پاس\s+ورڈ|خفیہ\s+نمبر', re.IGNORECASE), 0.3, "Password/PIN (Urdu)"),
        (re.compile(r'KYC.*اپڈیٹ|اپڈیٹ.*KYC', re.IGNORECASE), 0.4, "KYC update (Urdu)"),
    ],
    "en": [  # English phishing patterns (cross-language boosters)
        (re.compile(r'verify.*immediately|immediately.*verify', re.IGNORECASE), 0.3, "Urgent verify"),
        (re.compile(r'account.*suspend|suspend.*account', re.IGNORECASE), 0.4, "Account suspension"),
        (re.compile(r'click\s+here|log\s*in\s+immediately', re.IGNORECASE), 0.3, "Click here lure"),
        (re.compile(r'unauthorized|unauthorizd', re.IGNORECASE), 0.2, "Unauthorized reference"),
        (re.compile(r'enable\s+content|enable\s+macros', re.IGNORECASE), 0.5, "Macro enable request"),
        (re.compile(r'acknowledge\s+receipt.*benefits|benefits.*acknowledge', re.IGNORECASE), 0.3, "Benefits acknowledge lure"),
        (re.compile(r'open\s+the\s+attached.*html|attached.*html.*document', re.IGNORECASE), 0.5, "Attached HTML document"),
        (re.compile(r'acknowledge\s+(?:receipt|your|the)', re.IGNORECASE), 0.3, "Acknowledge lure"),
        (re.compile(r'Password_Update_Utility|network\s+drive.*reset|reset.*network\s+drive', re.IGNORECASE), 0.5, "Credential reset utility"),
        (re.compile(r'local\s+domain\s+controller|shared\s+network\s+drive.*password', re.IGNORECASE), 0.4, "Domain controller credential"),
        (re.compile(r'failure\s+to\s+comply.*result|result.*failure\s+to\s+comply', re.IGNORECASE), 0.3, "Threat of non-compliance"),
        (re.compile(r'voicemail.*html|html.*voicemail|playback.*html', re.IGNORECASE), 0.5, "HTML voicemail lure"),
        (re.compile(r'secure\s+recording|authenticate.*listen|listen.*authenticate', re.IGNORECASE), 0.4, "Fake secure recording"),
    ],
}

# ── Simple language hint patterns (fallback when langdetect unavailable) ─────
LANG_HINTS = {
    # Indian scripts
    "hi": re.compile(r'[\u0900-\u097F]'),        # Devanagari (Hindi, Marathi, Sanskrit)
    "mr": re.compile(r'[\u0900-\u097F]'),        # Devanagari (Marathi — same script as Hindi)
    "bn": re.compile(r'[\u0980-\u09FF]'),        # Bengali script
    "ta": re.compile(r'[\u0B80-\u0BFF]'),        # Tamil script
    "te": re.compile(r'[\u0C00-\u0C7F]'),        # Telugu script
    "kn": re.compile(r'[\u0C80-\u0CFF]'),        # Kannada script
    "ml": re.compile(r'[\u0D00-\u0D7F]'),        # Malayalam script
    "gu": re.compile(r'[\u0A80-\u0AFF]'),        # Gujarati script
    "pa": re.compile(r'[\u0A00-\u0A7F]'),        # Gurmukhi (Punjabi) script
    # Middle East / South Asia
    "ar": re.compile(r'[\u0600-\u06FF]'),         # Arabic / Urdu script
    "ur": re.compile(r'[\u0600-\u06FF]'),         # Urdu (shares Arabic script)
    # East Asia
    "zh": re.compile(r'[\u4E00-\u9FFF]'),         # CJK (Chinese)
    "ja": re.compile(r'[\u3040-\u309F\u30A0-\u30FF]'),  # Hiragana + Katakana
    "ko": re.compile(r'[\uAC00-\uD7AF]'),         # Hangul (Korean)
    # Eastern Europe
    "ru": re.compile(r'[\u0400-\u04FF]{3,}'),     # Cyrillic (Russian, Bulgarian, etc.)
}


def detect_languages(text: str) -> dict:
    """
    Detect languages in email text with per-sentence analysis.
    
    Returns:
        {
            "primary_language": "en",
            "languages_found": ["en", "hi"],
            "language_mix_ratio": 0.4,  # 0 = single language, 1 = highly mixed
            "is_mixed": bool,
            "sentence_analysis": [{"text": "...", "lang": "en"}],  # first 10
            "phishing_patterns": [{"lang": "hi", "pattern": "KYC lure", "weight": 0.3}],
            "risk_score": float
        }
    """
    if not text or not text.strip():
        return _empty_result()

    # Split into sentences — require min 15 chars to avoid langdetect misidentifying
    # short codes/fragments (e.g., "Issue: CRIT-102" detected as French)
    sentences = [s.strip() for s in SENT_RE.split(text) if s.strip() and len(s.strip()) > 15]
    if not sentences:
        return _empty_result()

    # Detect language per sentence
    lang_counts = {}
    sentence_analysis = []
    for sent in sentences[:50]:  # Cap at 50 sentences
        lang = _detect_sentence_lang(sent)
        lang_counts[lang] = lang_counts.get(lang, 0) + 1
        if len(sentence_analysis) < 10:
            sentence_analysis.append({"text": sent[:80], "lang": lang})

    # Compute primary language and mix ratio
    total = sum(lang_counts.values())
    primary = max(lang_counts, key=lang_counts.get)
    primary_ratio = lang_counts[primary] / total if total > 0 else 1.0
    mix_ratio = 1.0 - primary_ratio  # 0 = single language, higher = more mixed

    languages_found = sorted(lang_counts.keys())
    is_mixed = len(languages_found) > 1

    # Scan phishing patterns across all languages
    phishing_hits = []
    for lang, patterns in PHISHING_LEXICONS.items():
        for pattern_re, weight, desc in patterns:
            if pattern_re.search(text):
                phishing_hits.append({
                    "lang": lang,
                    "pattern": desc,
                    "weight": weight,
                })

    # Risk score: mixed language emails with phishing patterns are suspicious
    # IMPORTANT: Require meaningful hit weight - single generic words shouldn't trigger
    risk = 0.0
    if phishing_hits:
        total_weight = sum(h["weight"] for h in phishing_hits)
        # Only score if total pattern weight is meaningful (>= 0.4 or multiple hits)
        if total_weight >= 0.4 or len(phishing_hits) >= 2:
            risk = min(total_weight, 0.8)
        else:
            risk = 0.0  # Single low-weight hit = noise
    # Code-switching bonus only when actual phishing patterns found
    if is_mixed and risk > 0.0:
        risk = min(risk + 0.15, 0.9)
    elif is_mixed and len(languages_found) >= 3:
        # Very mixed (3+ languages) with no patterns: mildly suspicious
        risk = 0.2

    return {
        "primary_language": primary,
        "languages_found": languages_found,
        "language_mix_ratio": round(mix_ratio, 2),
        "is_mixed": is_mixed,
        "sentence_analysis": sentence_analysis,
        "phishing_patterns": phishing_hits,
        "risk_score": round(risk, 2),
    }


def _detect_sentence_lang(text: str) -> str:
    """Detect language of a single sentence."""
    # Quick check for non-Latin scripts
    for lang, pattern in LANG_HINTS.items():
        if pattern.search(text):
            return lang

    # Use langdetect if available
    if HAS_LANGDETECT:
        try:
            return _detect_lang(text)
        except (LangDetectException, Exception):
            pass

    return "en"  # Default


def _empty_result():
    return {
        "primary_language": "en",
        "languages_found": ["en"],
        "language_mix_ratio": 0.0,
        "is_mixed": False,
        "sentence_analysis": [],
        "phishing_patterns": [],
        "risk_score": 0.0,
    }
