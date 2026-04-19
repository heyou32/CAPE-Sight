"""
배치 분석 메인 클래스
"""
import json
import glob
import os
from datetime import datetime
from .ioc_extractor import IOCExtractor
from .report_generator import ReportGenerator
from .utils import ensure_directory
from config.settings import RISK_WEIGHTS

class BatchCapeAnalyzer:
    """배치 CAPE 분석 메인 클래스"""
    
    def __init__(self, input_folder, output_folder):
        self.input_folder = input_folder
        self.output_folder = output_folder
        
        # 폴더 생성
        ensure_directory(self.input_folder)
        ensure_directory(self.output_folder)
        ensure_directory(f"{self.output_folder}/individual_reports")
        
        # 컴포넌트 초기화
        self.ioc_extractor = IOCExtractor()
        self.report_generator = ReportGenerator(self.output_folder)
        
        # 결과 저장
        self.all_results = []
        self.failed_files = []
    
    def find_json_files(self):
        """JSON 파일들 찾기"""
        patterns = [
            f"{self.input_folder}/*.json",
            f"{self.input_folder}/**/*.json",
        ]
        
        json_files = []
        for pattern in patterns:
            json_files.extend(glob.glob(pattern, recursive=True))
        
        return list(set(json_files))
    
    def analyze_single_file(self, json_file):
        """단일 파일 분석"""
        try:
            print(f"📂 분석 중: {os.path.basename(json_file)}")
            
            # JSON 로드
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # IOC 추출
            iocs = self.ioc_extractor.extract_all_iocs(data)
            
            # 파일 정보 추출
            file_info = self._extract_file_info(data)
            
            # 통계 계산
            stats = self._calculate_stats(iocs)
            
            result = {
                'source_file': json_file,
                'file_info': file_info,
                'iocs': iocs,
                'stats': stats,
                'analysis_time': datetime.now().isoformat(),
                'status': 'success'
            }
            
            # 개별 보고서 생성
            self.report_generator.create_individual_report(result)
            
            print(f"   ✅ 완료 - 도메인: {len(iocs['domains'])}개, IP: {len(iocs['ips'])}개, 해시: {len(iocs['file_hashes'])}개")
            return result
            
        except Exception as e:
            error_result = {
                'source_file': json_file,
                'error': str(e),
                'status': 'failed',
                'analysis_time': datetime.now().isoformat()
            }
            print(f"   ❌ 실패: {str(e)}")
            return error_result
    
    def _extract_file_info(self, data):
        """파일 기본 정보 추출"""
        target = data.get('target', {}).get('file', {})
        info = data.get('info', {})
        
        return {
            'filename': target.get('name', 'Unknown'),
            'size': target.get('size', 0),
            'type': target.get('type', 'Unknown'),
            'md5': target.get('md5', ''),
            'sha1': target.get('sha1', ''),
            'sha256': target.get('sha256', ''),
            'analysis_id': info.get('id', ''),
            'started': info.get('started', ''),
            'duration': info.get('duration', 0),
            'machine': info.get('machine', {}).get('name', ''),
            'package': info.get('package', ''),
            'malscore': data.get('malscore', 0)
        }
    
    def _calculate_stats(self, iocs):
        """통계 계산"""
        enhanced_risk_score = self.ioc_extractor.calculate_enhanced_risk_score(iocs)
    
        return {
            'total_domains': len(iocs['domains']),
            'total_ips': len(iocs['ips']),
            'total_urls': len(iocs['urls']),
            'total_hashes': len(iocs['file_hashes']),
            'total_suspicious': len(iocs['suspicious_strings']),
            'pe_api_count': len(iocs.get('pe_analysis', {}).get('imports_analysis', [])),
            'behavioral_indicators': len(iocs.get('behavioral_indicators', [])),
            'packing_tools': len(iocs.get('packing_analysis', [])),
            'risk_score': enhanced_risk_score,  # ← 향상된 점수 사용
            'risk_breakdown': {
                'network_iocs': len(iocs['domains']) + len(iocs['ips']),
                'file_indicators': len(iocs['file_hashes']) + len(iocs['suspicious_strings']),
                'pe_analysis': len(iocs.get('pe_analysis', {}).get('imports_analysis', [])),
                'behavioral': len(iocs.get('behavioral_indicators', [])),
                'packing': len(iocs.get('packing_analysis', []))
            }
        }
        
    def run_batch_analysis(self):
        """배치 분석 실행"""
        print("🚀 CAPE 배치 분석 시작!\n")
        print(f"📁 입력 폴더: {self.input_folder}")
        print(f"📁 출력 폴더: {self.output_folder}")
        
        # JSON 파일들 찾기
        json_files = self.find_json_files()
        
        if not json_files:
            print(f"❌ {self.input_folder} 폴더에 JSON 파일이 없습니다!")
            return
        
        print(f"\n📊 발견된 JSON 파일: {len(json_files)}개")
        
        # 각 파일 분석
        for i, json_file in enumerate(json_files, 1):
            print(f"\n[{i}/{len(json_files)}] ", end="")
            result = self.analyze_single_file(json_file)
            
            if result['status'] == 'success':
                self.all_results.append(result)
            else:
                self.failed_files.append(result)
        
        # 통합 보고서 생성
        self.report_generator.create_summary_report(self.all_results, self.failed_files)
        self.report_generator.create_master_blacklist(self.all_results)
        
        print(f"\n🎉 배치 분석 완료!")
        print(f"   ✅ 성공: {len(self.all_results)}개")
        print(f"   ❌ 실패: {len(self.failed_files)}개")
        print(f"   📄 결과: {self.output_folder} 폴더 확인")