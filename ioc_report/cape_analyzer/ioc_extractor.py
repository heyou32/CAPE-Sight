"""
IOC 추출 전용 모듈 - PE 분석 포함
"""
from config.settings import SUSPICIOUS_KEYWORDS
from .utils import is_safe_domain, is_private_ip
from .pe_analyzer import PEAnalyzer

class IOCExtractor:
    """IOC 추출을 담당하는 클래스"""
    
    def __init__(self):
        # PE 분석기 초기화
        self.pe_analyzer = PEAnalyzer()
    
    def extract_all_iocs(self, data):
        """JSON 데이터에서 모든 IOC 추출"""
        iocs = {
            'domains': self.extract_domains(data),
            'ips': self.extract_ips(data),
            'urls': self.extract_urls(data),
            'file_hashes': self.extract_file_hashes(data),
            'suspicious_strings': self.extract_suspicious_strings(data),
            'pe_analysis': self.analyze_pe_file(data),  # ← PE 분석 사용
            'behavioral_indicators': self.extract_behavioral_indicators(data),
            'packing_analysis': self.analyze_executed_tools(data)
        }
        return iocs
    
    def extract_domains(self, data):
        """도메인 추출"""
        domains = []
        network = data.get('network', {})
        
        # HTTP 요청에서
        for http in network.get('http', []):
            if http.get('host') and not is_safe_domain(http['host']):
                if http['host'] not in domains:
                    domains.append(http['host'])
        
        # DNS 요청에서
        for dns in network.get('dns', []):
            if dns.get('request') and not is_safe_domain(dns['request']):
                if dns['request'] not in domains:
                    domains.append(dns['request'])
        
        return domains
    
    def extract_ips(self, data):
        """IP 주소 추출"""
        ips = []
        network = data.get('network', {})
        
        # TCP/UDP 연결에서
        for protocol in ['tcp', 'udp']:
            for conn in network.get(protocol, []):
                if conn.get('dst') and not is_private_ip(conn['dst']):
                    if conn['dst'] not in ips:
                        ips.append(conn['dst'])
        
        return ips
    
    def extract_urls(self, data):
        """URL 추출"""
        urls = []
        network = data.get('network', {})
        
        for http in network.get('http', []):
            if http.get('host') and http.get('uri'):
                url = f"http://{http['host']}{http['uri']}"
                if url not in urls:
                    urls.append(url)
        
        return urls
    
    def extract_file_hashes(self, data):
        """파일 해시 추출"""
        hashes = []
        
        # 원본 파일
        target = data.get('target', {}).get('file', {})
        for hash_type in ['md5', 'sha1', 'sha256']:
            if target.get(hash_type):
                hashes.append({
                    'hash': target[hash_type],
                    'type': hash_type,
                    'filename': target.get('name', 'unknown'),
                    'source': 'original_sample'
                })
        
        # 부모 샘플 (있는 경우)
        parent = data.get('info', {}).get('parent_sample', {})
        if parent:
            for hash_type in ['md5', 'sha1', 'sha256']:
                if parent.get(hash_type):
                    hashes.append({
                        'hash': parent[hash_type],
                        'type': hash_type,
                        'filename': 'parent_sample',
                        'source': 'parent_sample'
                    })
        
        # 드롭된 파일들
        for dropped in data.get('dropped', []):
            for hash_type in ['md5', 'sha1', 'sha256']:
                if dropped.get(hash_type):
                    hashes.append({
                        'hash': dropped[hash_type],
                        'type': hash_type,
                        'filename': dropped.get('name', 'unknown'),
                        'source': 'dropped_file'
                    })
        
        return hashes
    
    def extract_suspicious_strings(self, data):
        """의심스러운 문자열 추출"""
        suspicious = []
        
        # 파일 데이터에서
        file_data = data.get('target', {}).get('file', {}).get('data', '')
        if file_data:
            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword.lower() in file_data.lower():
                    suspicious.append({
                        'type': 'script_pattern',
                        'value': keyword,
                        'source': 'file_content'
                    })
        
        # strings 필드에서 패턴 검색 추가
        strings_data = data.get('target', {}).get('file', {}).get('strings', [])
        if strings_data:
            suspicious.extend(self.analyze_strings_patterns(strings_data))
        
        # 시그니처에서
        for sig in data.get('signatures', []):
            if sig.get('severity', 0) > 1:
                suspicious.append({
                    'type': 'signature',
                    'value': sig.get('name', ''),
                    'description': sig.get('description', ''),
                    'severity': sig.get('severity', 0)
                })
        
        return suspicious
    
    def analyze_strings_patterns(self, strings_list):
        """strings에서 의심스러운 패턴 분석 (간단한 버전)"""
        suspicious = []
        
        url_patterns = ['http://', 'https://', 'ftp://']
        
        for string in strings_list[:50]:  # 성능을 위해 50개만
            string_lower = string.lower()
            
            # URL 패턴만 간단히 체크
            for url_pattern in url_patterns:
                if url_pattern in string_lower and len(string) > 10:
                    suspicious.append({
                        'type': 'embedded_url',
                        'value': string,
                        'source': 'extracted_strings'
                    })
        
        return suspicious
    
    def analyze_pe_file(self, data):
        """PE 파일 분석 - pe_analyzer 모듈만 사용"""
        target = data.get('target', {}).get('file', {})
        
        # PE 파일이 아니면 빈 결과
        file_type = target.get('type', '')
        if 'PE32' not in file_type and 'executable' not in file_type:
            return {'is_pe_file': False}
        
        pe_data = target.get('pe', {})
        if not pe_data:
            return {'is_pe_file': True, 'analysis_failed': True}
        
        try:
            # PE Analyzer의 메소드들만 호출
            filename = target.get('name', '')
            
            # 파일명 분석 (pe_analyzer 사용)
            filename_analysis = self.pe_analyzer.analyze_filename_social_engineering(filename)
            
            # PE 구조 분석 (pe_analyzer 사용)
            pe_structure_analysis = self.pe_analyzer.analyze_pe_structure(pe_data)
            
            # 결과 조합
            return {
                'is_pe_file': True,
                'filename_analysis': filename_analysis,
                'imports_analysis': pe_structure_analysis['suspicious_imports'],
                'pe_indicators': pe_structure_analysis['risk_indicators'],
                'capabilities': pe_structure_analysis['capabilities']
            }
            
        except Exception as e:
            return {
                'is_pe_file': True,
                'analysis_failed': True,
                'error': str(e)
            }
    
    def extract_behavioral_indicators(self, data):
        """행동 기반 지표 추출 (네트워크/프로세스 행동만)"""
        indicators = []
        
        # 네트워크 행동 분석
        network = data.get('network', {})
        
        # 다중 호스트 통신
        http_requests = network.get('http', [])
        unique_hosts = list(set(req.get('host', '') for req in http_requests if req.get('host')))
        
        if len(unique_hosts) > 2:
            indicators.append({
                'type': 'multiple_host_communication',
                'description': f'{len(unique_hosts)}개의 다른 호스트와 통신',
                'risk_score': 5,
                'host_count': len(unique_hosts)
            })
        
        # DNS 쿼리 수 체크
        dns_requests = network.get('dns', [])
        if len(dns_requests) > 10:
            indicators.append({
                'type': 'excessive_dns_queries',
                'description': f'과도한 DNS 쿼리 ({len(dns_requests)}개)',
                'risk_score': 3,
                'query_count': len(dns_requests)
            })
        
        # 드롭된 파일 체크
        dropped_files = data.get('dropped', [])
        if len(dropped_files) > 0:
            indicators.append({
                'type': 'file_dropping_behavior',
                'description': f'{len(dropped_files)}개의 파일 생성',
                'risk_score': 4,
                'file_count': len(dropped_files)
            })
        
        # 프로세스 행동 (간단한 버전)
        behavior = data.get('behavior', {})
        processes = behavior.get('processes', [])
        
        if len(processes) > 1:
            indicators.append({
                'type': 'multiple_processes',
                'description': f'{len(processes)}개의 프로세스 실행',
                'risk_score': 3,
                'process_count': len(processes)
            })
        
        return indicators
    
    def analyze_executed_tools(self, data):
        """실행된 도구들로 악성코드 특성 분석"""
        executed_tools = data.get('target', {}).get('file', {}).get('executed_tools', [])
        
        tool_indicators = []
        
        # 패킹/난독화 도구들
        packing_tools = {
            'UPX_unpack': {'risk_score': 6, 'description': 'UPX 패킹 (일반적 패커)'},
            'Themida_unpack': {'risk_score': 9, 'description': 'Themida 패킹 (고급 보호)'},
            'de4dot_deobfuscate': {'risk_score': 7, 'description': '.NET 난독화'},
            'eziriz_deobfuscate': {'risk_score': 8, 'description': '상용 난독화 도구'},
            'VMProtect_unpack': {'risk_score': 9, 'description': 'VMProtect (매우 고급)'}
        }
        
        for tool in executed_tools:
            if tool in packing_tools:
                tool_info = packing_tools[tool]
                tool_indicators.append({
                    'type': 'packing_obfuscation',
                    'tool': tool,
                    'risk_score': tool_info['risk_score'],
                    'description': tool_info['description']
                })
        
        return tool_indicators

    def calculate_enhanced_risk_score(self, iocs):  # ← 이 함수를 추가하세요!
        """네트워크 IOC가 없어도 위험도 계산"""
        
        score = 0
        
        # 1. 기본 IOC (네트워크 있으면 높은 점수)
        score += len(iocs['domains']) * 15
        score += len(iocs['ips']) * 20
        score += len(iocs['urls']) * 10
        
        # 2. 정적 분석 (항상 가능)
        score += len(iocs['file_hashes']) * 2  # 파일 해시 존재
        score += len(iocs['suspicious_strings']) * 8  # 5 → 8로 증가
        
        # 3. PE 분석 (PE 파일인 경우)
        pe_analysis = iocs.get('pe_analysis', {})
        if pe_analysis.get('is_pe_file'):
            # PE 파일 기본 점수
            score += 15
            
            # 의심스러운 API 점수
            for api in pe_analysis.get('imports_analysis', []):
                score += api.get('risk_level', 0)
            
            # 파일명 분석 점수
            for indicator in pe_analysis.get('filename_analysis', []):
                score += indicator.get('risk_score', 0)
            
            # PE 지표 점수
            for indicator in pe_analysis.get('pe_indicators', []):
                score += indicator.get('risk_score', 0)
        
        # 4. 패킹/난독화 점수
        for packing in iocs.get('packing_analysis', []):
            score += packing.get('risk_score', 0)
        
        # 5. 행동 지표 점수
        for behavior in iocs.get('behavioral_indicators', []):
            score += behavior.get('risk_score', 0)
        
        
        return min(score, 100)