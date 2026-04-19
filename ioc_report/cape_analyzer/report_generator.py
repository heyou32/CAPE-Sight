"""
보고서 생성 전용 모듈
"""
import csv
from datetime import datetime
from .utils import sanitize_filename, format_file_size

class ReportGenerator:
    """보고서 생성을 담당하는 클래스"""
    
    def __init__(self, output_folder):
        self.output_folder = output_folder
    
    def create_individual_report(self, result):
        """개별 파일 보고서 생성"""
        if result['status'] != 'success':
            return
            
        safe_filename = sanitize_filename(result['file_info']['filename'])
        filename = f"individual_{result['file_info']['analysis_id']}_{safe_filename}.txt"
        filepath = f"{self.output_folder}/individual_reports/{filename}"
        
        # 디버깅 정보 추가
        print(f"   📝 개별 보고서 생성 시도:")
        print(f"      - 파일명: {filename}")
        print(f"      - 경로: {filepath}")
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                self._write_individual_report_content(f, result)
            print(f"   ✅ 개별 보고서 생성 성공: {filename}")
            
        except Exception as e:
            print(f"   ❌ 개별 보고서 생성 실패: {str(e)}")
    
    def _write_individual_report_content(self, f, result):
        """개별 보고서 내용 작성 - 상세 위험도 계산 포함"""
        info = result['file_info']
        stats = result['stats'] 
        iocs = result['iocs']
        
        f.write("=" * 80 + "\n")
        f.write(f"🛡️  CAPE 개별 분석 보고서 - {info['filename']}\n")
        f.write("=" * 80 + "\n\n")
        
        # 위험도 요약 (가장 먼저 표시)
        risk_score = stats['risk_score']
        risk_level = self._get_risk_level(risk_score)
        f.write(f"🎯 위험도 평가: {risk_score}/100점 ({risk_level})\n")
        f.write("=" * 50 + "\n\n")
        
        # 파일 기본 정보
        f.write("[📋 파일 정보]\n")
        f.write(f"파일명: {info['filename']}\n")
        f.write(f"크기: {self._format_file_size(info['size'])}\n")
        f.write(f"파일 타입: {info['type']}\n")
        f.write(f"MD5: {info['md5']}\n")
        f.write(f"SHA1: {info['sha1']}\n")
        f.write(f"SHA256: {info['sha256']}\n")
        f.write(f"분석 ID: {info['analysis_id']}\n")
        f.write(f"분석 시작: {info['started']}\n")
        f.write(f"분석 시간: {info['duration']}초\n")
        f.write(f"분석 머신: {info['machine']}\n\n")
        
        # IOC 통계
        f.write("[📊 IOC 통계]\n")
        f.write(f"악성 도메인: {stats['total_domains']}개\n")
        f.write(f"C&C IP: {stats['total_ips']}개\n")
        f.write(f"악성 URL: {stats['total_urls']}개\n")
        f.write(f"파일 해시: {stats['total_hashes']}개\n")
        f.write(f"PE API: {stats.get('pe_api_count', 0)}개\n")
        f.write(f"행동 지표: {stats.get('behavioral_indicators', 0)}개\n")
        f.write(f"패킹 도구: {stats.get('packing_tools', 0)}개\n\n")
        
        # ✨ 위험도 계산 상세 분석 (새로 추가!)
        self._write_risk_calculation_details(f, iocs, stats)
        
        # 상세 IOC 분석
        if iocs['domains']:
            f.write(f"[🌐 발견된 악성 도메인 ({len(iocs['domains'])}개)]\n")
            for i, domain in enumerate(iocs['domains'], 1):
                f.write(f"{i:2d}. {domain}\n")
            f.write("\n")
        
        if iocs['ips']:
            f.write(f"[🎯 발견된 C&C IP ({len(iocs['ips'])}개)]\n")
            for i, ip in enumerate(iocs['ips'], 1):
                f.write(f"{i:2d}. {ip}\n")
            f.write("\n")
        
        if iocs['urls']:
            f.write(f"[🔗 발견된 악성 URL ({len(iocs['urls'])}개)]\n")
            for i, url in enumerate(iocs['urls'], 1):
                f.write(f"{i:2d}. {url}\n")
            f.write("\n")
        
        # ✨ PE 분석 상세 정보 (새로 추가!)
        self._write_pe_analysis_details(f, iocs)
        
        # ✨ 의심스러운 패턴 상세 분석 (새로 추가!)
        self._write_suspicious_patterns_details(f, iocs)
        
        # ✨ 행동 분석 상세 정보 (새로 추가!)
        self._write_behavioral_analysis_details(f, iocs)
        
        # ✨ 패킹/난독화 분석 (새로 추가!)
        self._write_packing_analysis_details(f, iocs)
        
        if iocs['file_hashes']:
            f.write(f"[📄 파일 해시 ({len(iocs['file_hashes'])}개)]\n")
            for i, hash_info in enumerate(iocs['file_hashes'], 1):
                f.write(f"{i:2d}. {hash_info['type'].upper()}: {hash_info['hash']}\n")
                f.write(f"     파일: {hash_info['filename']} ({hash_info['source']})\n")
            f.write("\n")
        
        # 대응 권고사항
        f.write("[🔧 대응 권고사항]\n")
        recommendations = self._generate_recommendations(iocs, stats)
        for i, rec in enumerate(recommendations, 1):
            f.write(f"{i}. {rec}\n")

    def _write_risk_calculation_details(self, f, iocs, stats):
        """위험도 계산 과정 상세 표시"""
        f.write("[🧮 위험도 계산 상세]\n")
        
        # 각 카테고리별 점수 계산 및 표시
        network_score = len(iocs['domains']) * 15 + len(iocs['ips']) * 20 + len(iocs['urls']) * 10
        file_score = len(iocs['file_hashes']) * 2 + len(iocs['suspicious_strings']) * 8
        
        f.write(f"📡 네트워크 IOC 점수: {network_score}점\n")
        if len(iocs['domains']) > 0:
            f.write(f"   - 악성 도메인: {len(iocs['domains'])}개 × 15점 = {len(iocs['domains']) * 15}점\n")
        if len(iocs['ips']) > 0:
            f.write(f"   - C&C IP: {len(iocs['ips'])}개 × 20점 = {len(iocs['ips']) * 20}점\n")
        if len(iocs['urls']) > 0:
            f.write(f"   - 악성 URL: {len(iocs['urls'])}개 × 10점 = {len(iocs['urls']) * 10}점\n")
        
        f.write(f"\n📁 파일 기반 점수: {file_score}점\n")
        if len(iocs['file_hashes']) > 0:
            f.write(f"   - 파일 해시: {len(iocs['file_hashes'])}개 × 2점 = {len(iocs['file_hashes']) * 2}점\n")
        if len(iocs['suspicious_strings']) > 0:
            f.write(f"   - 의심 패턴: {len(iocs['suspicious_strings'])}개 × 8점 = {len(iocs['suspicious_strings']) * 8}점\n")
        
        # PE 분석 점수
        pe_analysis = iocs.get('pe_analysis', {})
        pe_score = 0
        if pe_analysis.get('is_pe_file'):
            pe_score += 15  # 기본 점수
            api_score = sum(api.get('risk_level', 0) for api in pe_analysis.get('imports_analysis', []))
            filename_score = sum(ind.get('risk_score', 0) for ind in pe_analysis.get('filename_analysis', []))
            pe_indicators_score = sum(ind.get('risk_score', 0) for ind in pe_analysis.get('pe_indicators', []))
            
            pe_score += api_score + filename_score + pe_indicators_score
            
            f.write(f"\n💻 PE 분석 점수: {pe_score}점\n")
            f.write(f"   - PE 파일 기본: 15점\n")
            if api_score > 0:
                f.write(f"   - 위험한 API: {api_score}점\n")
            if filename_score > 0:
                f.write(f"   - 의심 파일명: {filename_score}점\n")
            if pe_indicators_score > 0:
                f.write(f"   - PE 구조 위험: {pe_indicators_score}점\n")
        
        # 패킹/행동 점수
        packing_score = sum(pack.get('risk_score', 0) for pack in iocs.get('packing_analysis', []))
        behavior_score = sum(beh.get('risk_score', 0) for beh in iocs.get('behavioral_indicators', []))
        
        if packing_score > 0:
            f.write(f"\n📦 패킹/난독화 점수: {packing_score}점\n")
        if behavior_score > 0:
            f.write(f"\n🎭 행동 패턴 점수: {behavior_score}점\n")
        
        
    def _write_pe_analysis_details(self, f, iocs):
        """PE 분석 상세 정보"""
        pe_analysis = iocs.get('pe_analysis', {})
        
        if not pe_analysis.get('is_pe_file'):
            return
        
        f.write("[💻 PE 파일 분석 상세]\n")
        
        # 파일명 분석
        filename_analysis = pe_analysis.get('filename_analysis', [])
        if filename_analysis:
            f.write("📝 파일명 분석:\n")
            for indicator in filename_analysis:
                f.write(f"   - {indicator['type']}: {indicator['description']} (위험도: {indicator.get('risk_score', 0)}점)\n")
            f.write("\n")
        
        # API 분석
        imports_analysis = pe_analysis.get('imports_analysis', [])
        if imports_analysis:
            f.write("🔧 발견된 위험한 API 함수들:\n")
            
            # 카테고리별로 그룹화
            api_by_category = {}
            for api in imports_analysis:
                category = api.get('category', 'unknown')
                if category not in api_by_category:
                    api_by_category[category] = []
                api_by_category[category].append(api)
            
            for category, apis in api_by_category.items():
                f.write(f"\n   📂 {category}:\n")
                for api in apis:
                    f.write(f"      - {api['api']} (위험도: {api.get('risk_level', 0)}점)\n")
                    f.write(f"        DLL: {api['dll']}, 주소: {api.get('address', 'N/A')}\n")
            f.write("\n")
        
        # PE 구조 지표
        pe_indicators = pe_analysis.get('pe_indicators', [])
        if pe_indicators:
            f.write("🏗️ PE 구조 위험 지표:\n")
            for indicator in pe_indicators:
                f.write(f"   - {indicator['type']}: {indicator['description']}")
                if 'risk_score' in indicator:
                    f.write(f" (위험도: {indicator['risk_score']}점)")
                f.write("\n")
            f.write("\n")

    def _write_suspicious_patterns_details(self, f, iocs):
        """의심스러운 패턴 상세 분석"""
        suspicious_strings = iocs.get('suspicious_strings', [])
        
        if not suspicious_strings:
            return
        
        f.write(f"[⚠️ 발견된 의심스러운 패턴 ({len(suspicious_strings)}개)]\n")
        
        # 타입별로 그룹화
        patterns_by_type = {}
        for pattern in suspicious_strings:
            pattern_type = pattern.get('type', 'unknown')
            if pattern_type not in patterns_by_type:
                patterns_by_type[pattern_type] = []
            patterns_by_type[pattern_type].append(pattern)
        
        for pattern_type, patterns in patterns_by_type.items():
            f.write(f"\n📂 {pattern_type}:\n")
            for pattern in patterns:
                f.write(f"   - {pattern['value']}")
                if 'description' in pattern:
                    f.write(f" ({pattern['description']})")
                if 'severity' in pattern:
                    f.write(f" [심각도: {pattern['severity']}]")
                if 'source' in pattern:
                    f.write(f" [출처: {pattern['source']}]")
                f.write("\n")
                
                # 컨텍스트 정보가 있으면 표시
                if 'context' in pattern and pattern['context']:
                    f.write(f"     컨텍스트: {pattern['context'][:100]}...\n")
        
        f.write("\n")

    def _write_behavioral_analysis_details(self, f, iocs):
        """행동 분석 상세 정보"""
        behavioral_indicators = iocs.get('behavioral_indicators', [])
        
        if not behavioral_indicators:
            f.write("[🎭 행동 분석]\n")
            f.write("특별한 행동 패턴이 감지되지 않았습니다.\n")
            f.write("(샌드박스 회피 또는 조건부 실행 가능성)\n\n")
            return
        
        f.write(f"[🎭 행동 분석 ({len(behavioral_indicators)}개 지표)]\n")
        
        for indicator in behavioral_indicators:
            f.write(f"🔸 {indicator['type']}: {indicator['description']}\n")
            f.write(f"   위험도: {indicator.get('risk_score', 0)}점\n")
            
            # 추가 상세 정보
            for key, value in indicator.items():
                if key not in ['type', 'description', 'risk_score']:
                    f.write(f"   {key}: {value}\n")
            f.write("\n")

    def _write_packing_analysis_details(self, f, iocs):
        """패킹/난독화 분석 상세"""
        packing_analysis = iocs.get('packing_analysis', [])
        
        if not packing_analysis:
            return
        
        f.write(f"[📦 패킹/난독화 분석 ({len(packing_analysis)}개 도구)]\n")
        
        for packing in packing_analysis:
            f.write(f"🔧 {packing['tool']}: {packing['description']}\n")
            f.write(f"   위험도: {packing.get('risk_score', 0)}점\n")
            f.write(f"   유형: {packing.get('type', 'unknown')}\n\n")

    def _generate_recommendations(self, iocs, stats):
        """위험도와 IOC 기반 맞춤형 대응 권고사항 생성"""
        recommendations = []
        
        risk_score = stats['risk_score']
        
        # 위험도별 기본 권고사항
        if risk_score >= 80:
            recommendations.append("🚨 즉시 격리 필요 - 매우 높은 위험도")
            recommendations.append("경영진 및 보안팀 즉시 보고")
        elif risk_score >= 60:
            recommendations.append("⚠️ 우선 대응 필요 - 높은 위험도")
            recommendations.append("4시간 내 상세 분석 및 대응")
        elif risk_score >= 40:
            recommendations.append("📊 모니터링 강화 - 보통 위험도")
            recommendations.append("24시간 내 검토 및 대응")
        else:
            recommendations.append("👀 지속 관찰 - 낮은 위험도")
            recommendations.append("주간 검토 대상으로 분류")
        
        # IOC별 맞춤 권고사항
        if len(iocs['domains']) > 0 or len(iocs['ips']) > 0:
            recommendations.append("방화벽에서 발견된 도메인/IP 즉시 차단")
            recommendations.append("DNS 싱크홀 설정 고려")
        
        if len(iocs['file_hashes']) > 0:
            recommendations.append("발견된 파일 해시를 백신 블랙리스트에 추가")
            recommendations.append("EDR에서 해당 해시 파일 검색 실행")
        
        pe_analysis = iocs.get('pe_analysis', {})
        if pe_analysis.get('is_pe_file') and len(pe_analysis.get('imports_analysis', [])) > 0:
            recommendations.append("위험한 API 사용 패턴 모니터링 강화")
            recommendations.append("프로세스 인젝션 탐지 룰 업데이트")
        
        if len(iocs.get('packing_analysis', [])) > 0:
            recommendations.append("패킹/난독화된 파일에 대한 심층 분석 수행")
            recommendations.append("언패킹 도구를 활용한 추가 분석 권장")
        
        if len(iocs['suspicious_strings']) > 0:
            recommendations.append("발견된 의심 패턴에 대한 YARA 룰 생성")
            recommendations.append("스크립트 실행 모니터링 강화")
        
        return recommendations

    def _get_risk_level(self, score):
        """위험도 점수를 레벨로 변환"""
        if score >= 80:
            return "매우 높음 🔴"
        elif score >= 60:
            return "높음 🟠"
        elif score >= 40:
            return "보통 🟡"
        elif score >= 20:
            return "낮음 🟢"
        else:
            return "미미함 ⚪"

    def _format_file_size(self, size_bytes):
        """파일 크기 포맷팅"""
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        
        return f"{size_bytes:.1f} {size_names[i]}"
    
    def create_summary_report(self, all_results, failed_files):
        """통합 요약 보고서 생성"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{self.output_folder}/summary_report_{timestamp}.txt"
        
        with open(filename, 'w', encoding='utf-8') as f:
            self._write_summary_content(f, all_results, failed_files)
        
        print(f"📊 통합 보고서 생성: {filename}")
        return filename
    
    def _write_summary_content(self, f, all_results, failed_files):
        """요약 보고서 내용 작성"""
        f.write("=" * 80 + "\n")
        f.write("🛡️ CAPE 배치 분석 통합 보고서\n")
        f.write("=" * 80 + "\n\n")
        
        f.write(f"📅 분석 일시: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"✅ 처리된 파일: {len(all_results)}개\n")
        f.write(f"❌ 실패한 파일: {len(failed_files)}개\n\n")
        
        # 전체 통계
        total_domains = sum(len(r['iocs']['domains']) for r in all_results)
        total_ips = sum(len(r['iocs']['ips']) for r in all_results)
        total_hashes = sum(len(r['iocs']['file_hashes']) for r in all_results)
        
        f.write("[📊 전체 IOC 통계]\n")
        f.write(f"🌐 총 악성 도메인: {total_domains}개\n")
        f.write(f"🎯 총 C&C IP: {total_ips}개\n")
        f.write(f"📄 총 파일 해시: {total_hashes}개\n\n")
        
        # 고위험 파일들
        high_risk_files = [r for r in all_results if r['stats']['risk_score'] >= 60]
        
        f.write(f"[⚠️ 고위험 파일 ({len(high_risk_files)}개)]\n")
        if high_risk_files:
            for result in sorted(high_risk_files, key=lambda x: x['stats']['risk_score'], reverse=True):
                f.write(f"- {result['file_info']['filename']} (위험도: {result['stats']['risk_score']}점)\n")
        else:
            f.write("고위험 파일이 발견되지 않았습니다.\n")
        
        f.write(f"\n[📋 처리된 모든 파일]\n")
        for i, result in enumerate(all_results, 1):
            info = result['file_info']
            stats = result['stats']
            f.write(f"{i:2d}. {info['filename']}\n")
            f.write(f"     🆔 ID: {info['analysis_id']}, 📏 크기: {format_file_size(info['size'])}\n")
            f.write(f"     📊 IOC: 도메인 {stats['total_domains']}개, IP {stats['total_ips']}개\n")
            f.write(f"     ⚠️ 위험도: {stats['risk_score']}/100점\n\n")
    
    def create_master_blacklist(self, all_results):
        """마스터 블랙리스트 생성"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        csv_filename = f"{self.output_folder}/master_blacklist_{timestamp}.csv"
        
        with open(csv_filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['타입', 'IOC', '설명', '출처파일', '분석ID'])
            
            for result in all_results:
                source_info = f"{result['file_info']['filename']} (ID:{result['file_info']['analysis_id']})"
                
                # 도메인
                for domain in result['iocs']['domains']:
                    writer.writerow(['도메인', domain, 'C&C 서버 도메인', source_info, result['file_info']['analysis_id']])
                
                # IP
                for ip in result['iocs']['ips']:
                    writer.writerow(['IP', ip, 'C&C 서버 IP', source_info, result['file_info']['analysis_id']])
                
                # 파일 해시
                for hash_info in result['iocs']['file_hashes']:
                    writer.writerow(['파일해시', hash_info['hash'], 
                                   f"악성파일 해시 ({hash_info['type'].upper()})", 
                                   source_info, result['file_info']['analysis_id']])
        
        print(f"📋 마스터 블랙리스트 생성: {csv_filename}")
        return csv_filename