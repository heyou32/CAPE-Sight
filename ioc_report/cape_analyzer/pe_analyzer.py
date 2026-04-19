"""
PE 파일 분석 전용 모듈
"""

class PEAnalyzer:
    """PE 파일 특화 분석"""
    
    def __init__(self):
        # 의심스러운 API 함수들
        self.suspicious_apis = {
            'registry_manipulation': [
                'RegCreateKeyExA', 'RegSetValueExA', 'RegDeleteKeyA', 
                'RegDeleteValueA', 'RegOpenKeyExA'
            ],
            'privilege_escalation': [
                'AdjustTokenPrivileges', 'LookupPrivilegeValueA', 
                'OpenProcessToken'
            ],
            'file_operations': [
                'SHFileOperationA', 'ShellExecuteExA'
            ],
            'process_manipulation': [
                'CreateProcessA', 'OpenProcess', 'WriteProcessMemory'
            ],
            'network_operations': [
                'WSAStartup', 'connect', 'send', 'recv', 'InternetOpenA'
            ]
        }
        
        # 의심스러운 파일명 패턴
        self.suspicious_filename_patterns = [
            'invoice', 'receipt', 'document', 'photo', 'image',
            'bonus', 'salary', 'payment', 'urgent', 'important',
            'confidential', 'secure', 'update', 'patch'
        ]
    
    def analyze_pe_structure(self, pe_data):
        """PE 구조 분석"""
        analysis = {
            'suspicious_imports': [],
            'risk_indicators': [],
            'capabilities': []
        }
        
        if not pe_data:
            return analysis
        
        # Import 분석
        imports = pe_data.get('imports', {})
        analysis['suspicious_imports'] = self.analyze_imports(imports)
        
        # 기본 PE 정보 분석
        analysis['risk_indicators'] = self.analyze_pe_indicators(pe_data)
        
        return analysis
    
    def analyze_imports(self, imports):
        """Import된 API 함수 분석"""
        found_apis = []
        
        for dll_name, dll_info in imports.items():
            dll_imports = dll_info.get('imports', [])
            
            for imp in dll_imports:
                api_name = imp.get('name', '')
                
                # 각 카테고리별로 체크
                for category, api_list in self.suspicious_apis.items():
                    if api_name in api_list:
                        found_apis.append({
                            'api': api_name,
                            'dll': dll_name,
                            'category': category,
                            'address': imp.get('address', ''),
                            'risk_level': self.get_api_risk_level(category)
                        })
        
        return found_apis
    
    def get_api_risk_level(self, category):
        """API 카테고리별 위험도"""
        risk_levels = {
            'registry_manipulation': 7,     # 지속성 확보
            'privilege_escalation': 9,      # 권한 상승 (매우 위험)
            'file_operations': 5,           # 파일 조작
            'process_manipulation': 8,      # 프로세스 조작 (높은 위험)
            'network_operations': 6         # 네트워크 통신
        }
        return risk_levels.get(category, 3)
    
    def analyze_pe_indicators(self, pe_data):
        """PE 파일의 위험 지표 분석"""
        indicators = []
        
        # 디지털 서명 체크
        signers = pe_data.get('digital_signers', [])
        if not signers:
            indicators.append({
                'type': 'no_digital_signature',
                'description': '디지털 서명 없음',
                'risk_score': 5
            })
        
        # 엔트리포인트 체크
        entrypoint = pe_data.get('entrypoint', '')
        if entrypoint:
            indicators.append({
                'type': 'entrypoint',
                'value': entrypoint,
                'description': 'PE 진입점'
            })
        
        # 체크섬 검증
        reported_checksum = pe_data.get('reported_checksum', '')
        actual_checksum = pe_data.get('actual_checksum', '')
        if reported_checksum != actual_checksum:
            indicators.append({
                'type': 'checksum_mismatch',
                'description': '체크섬 불일치 (파일 변조 가능성)',
                'risk_score': 6
            })
        
        return indicators
    
    def analyze_filename_social_engineering(self, filename):
        """파일명 사회공학적 분석"""
        suspicious_indicators = []
        
        filename_lower = filename.lower()
        
        # 의심스러운 키워드 체크
        for pattern in self.suspicious_filename_patterns:
            if pattern in filename_lower:
                suspicious_indicators.append({
                    'type': 'social_engineering_filename',
                    'pattern': pattern,
                    'description': f'사회공학적 파일명 패턴: {pattern}',
                    'risk_score': 4
                })
        
        # 확장자 이중 사용 체크 (예: document.pdf.exe)
        if filename_lower.count('.') > 1:
            suspicious_indicators.append({
                'type': 'double_extension',
                'description': '이중 확장자 (사용자 혼동 목적)',
                'risk_score': 7
            })
        
        # 공백이나 특수문자 많이 사용
        if len([c for c in filename if c in ' \t\n']) > 2:
            suspicious_indicators.append({
                'type': 'suspicious_spacing',
                'description': '의심스러운 공백 사용',
                'risk_score': 3
            })
        
        return suspicious_indicators