"""
CAPE 분석기 설정 파일
"""

# 기본 폴더 설정
DEFAULT_INPUT_FOLDER = "cape_results"
DEFAULT_OUTPUT_FOLDER = "batch_output"

# 안전한 도메인 화이트리스트
SAFE_DOMAINS = [
    'microsoft.com', 'google.com', 'adobe.com', 'mozilla.org',
    'windows.com', 'apple.com', 'github.com', 'stackoverflow.com'
]

# 의심스러운 키워드들
SUSPICIOUS_KEYWORDS = [
    'ActiveXObject', 'WScript.Shell', 'cmd.exe', 'powershell',
    'eval(', 'unescape(', 'XMLHttpRequest', 'downloadstring',
    'invoke-expression', 'base64', 'fromcharcode'
]

# 위험도 점수 가중치
RISK_WEIGHTS = {
    'domain': 15,
    'ip': 20,
    'url': 10,
    'suspicious_string': 5
}

# 고위험 임계값
HIGH_RISK_THRESHOLD = 50