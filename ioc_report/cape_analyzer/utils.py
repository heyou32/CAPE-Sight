"""
유틸리티 함수들
"""
import os
from config.settings import SAFE_DOMAINS

def is_safe_domain(domain):
    """안전한 도메인 체크"""
    return any(safe in domain.lower() for safe in SAFE_DOMAINS)

def is_private_ip(ip):
    """사설 IP 체크"""
    return (ip.startswith('192.168.') or ip.startswith('10.') or 
            ip.startswith('127.') or ip == '0.0.0.0' or ip.startswith('172.'))

def sanitize_filename(filename):
    """파일명을 안전하게 변환"""
    return filename.replace('/', '_').replace('\\', '_').replace(':', '_')

def ensure_directory(directory):
    """디렉토리가 없으면 생성"""
    os.makedirs(directory, exist_ok=True)

def format_file_size(size_bytes):
    """파일 크기를 읽기 쉽게 포맷"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f} {size_names[i]}"