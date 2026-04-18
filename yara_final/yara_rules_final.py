import json
import os
import glob
import re
from datetime import datetime
from colorama import init, Fore, Style
import time

init()

class FinalCapeScanner:
    def __init__(self, rules_file="yara_rules_final.yar"):
        self.rules = []
        self.matches = []
        self.risk_levels = {
            1: {"name": "CRITICAL", "color": Fore.RED, "symbol": "🚨"},
            2: {"name": "HIGH", "color": Fore.YELLOW, "symbol": "⚠️"},
            3: {"name": "HIGH", "color": Fore.YELLOW, "symbol": "⚠️"},
            4: {"name": "HIGH", "color": Fore.YELLOW, "symbol": "⚠️"},
            5: {"name": "HIGH", "color": Fore.YELLOW, "symbol": "⚠️"},
            6: {"name": "MEDIUM", "color": Fore.CYAN, "symbol": "🔍"},
            7: {"name": "MEDIUM", "color": Fore.CYAN, "symbol": "🔍"},
            8: {"name": "MEDIUM", "color": Fore.CYAN, "symbol": "🔍"},
            9: {"name": "MEDIUM", "color": Fore.CYAN, "symbol": "🔍"},
            10: {"name": "MEDIUM", "color": Fore.CYAN, "symbol": "🔍"}
        }
        self.load_rules(rules_file)
    
    def load_rules(self, rules_file):
        """YARA 룰 로드 (간결 버전)"""
        print(f"{Fore.YELLOW}📋 YARA 룰셋 로딩 중...{Style.RESET_ALL}")
        
        try:
            with open(rules_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 룰별로 분리
            rule_blocks = re.findall(r'rule\s+(\w+)\s*\{(.*?)\n\}', content, re.DOTALL)
            
            for rule_name, rule_content in rule_blocks:
                # 우선순위와 심각도 추출
                priority = 99
                severity = "UNKNOWN"
                
                meta_match = re.search(r'priority\s*=\s*(\d+)', rule_content)
                severity_match = re.search(r'severity\s*=\s*"(\w+)"', rule_content)
                
                if meta_match:
                    priority = int(meta_match.group(1))
                if severity_match:
                    severity = severity_match.group(1)
                
                # strings 섹션 추출
                strings = []
                strings_match = re.search(r'strings:(.*?)condition:', rule_content, re.DOTALL)
                
                if strings_match:
                    for line in strings_match.group(1).split('\n'):
                        if '$' in line and '=' in line:
                            var_name = line.strip().split('=')[0].strip()
                            string_value = re.findall(r'"([^"]*)"', line)
                            if string_value:
                                strings.append((var_name, string_value[0]))
                
                # condition 추출
                condition_match = re.search(r'condition:\s*(.*)', rule_content, re.DOTALL)
                condition = condition_match.group(1).strip() if condition_match else ""
                
                self.rules.append({
                    'name': rule_name,
                    'strings': strings,
                    'condition': condition,
                    'priority': priority,
                    'severity': severity
                })
            
            # 우선순위별로 정렬
            self.rules.sort(key=lambda x: x['priority'])
            
            print(f"   ✅ {Fore.GREEN}{len(self.rules)}개{Style.RESET_ALL} 룰 로드 완료")
            
            # 간단한 통계
            priority_count = {}
            for rule in self.rules:
                severity = rule['severity']
                priority_count[severity] = priority_count.get(severity, 0) + 1
            
            print(f"   📊 위험도별 분포:")
            for level, count in priority_count.items():
                color = Fore.RED if level == "CRITICAL" else \
                       Fore.YELLOW if level == "HIGH" else \
                       Fore.CYAN if level == "MEDIUM" else Fore.GREEN
                print(f"      └── {color}{level}: {count}개{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"❌ 룰 로딩 오류: {e}")
    
    def get_matches(self, rule, file_type, file_hash, strings_list):
        """매치된 패턴들 찾기 (기존 방식)"""
        matches = []
        
        for var_name, pattern in rule['strings']:
            # 해시 우선 검사
            if pattern.lower() in file_hash.lower():
                matches.append(f"{var_name}: '{pattern}' (hash)")
                continue
            
            # 파일 타입 검사
            if pattern.lower() in file_type.lower():
                matches.append(f"{var_name}: '{pattern}' (filetype)")
                continue
            
            # 문자열 리스트 검사
            for s in strings_list:
                if pattern.lower() in s.lower():
                    matches.append(f"{var_name}: '{pattern}' (strings)")
                    break
        
        return matches
    
    def evaluate_condition(self, rule, matched_items):
        """조건 평가 (기존 방식 + 일부 개선)"""
        condition = rule['condition'].lower()
        match_count = len(matched_items)
        
        # 특별 룰 처리
        if rule['name'] == 'Known_Malware_Hash':
            return match_count > 0
        
        if rule['name'] == 'Suspicious_PE_Executable':
            # PE 조건 + 2개 이상 API
            pe_found = any('pe32' in item.lower() or 'executable' in item.lower() for item in matched_items)
            api_count = sum(1 for item in matched_items if any(api in item.lower() for api in 
                          ['createremotethread', 'virtualallocex', 'writeprocessmemory']))
            return pe_found and api_count >= 2
        
        # 일반 조건
        if 'any of them' in condition or 'any of ($' in condition:
            return match_count > 0
        elif '2 of' in condition:
            return match_count >= 2
        elif '3 of' in condition:
            return match_count >= 3
        elif '1 of' in condition:
            return match_count >= 1
        elif 'and' in condition:
            required_vars = len([s for s in rule['strings']])
            return match_count >= min(2, required_vars)
        else:
            return match_count > 0
    
    def check_json_file(self, json_file):
        """JSON 파일 검사 (기존 방식)"""
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            target = data.get('target', {}).get('file', {})
            file_type = target.get('type', '')
            file_hash = target.get('sha256', '')
            strings_list = target.get('strings', [])
            
            for rule in self.rules:
                matched_items = self.get_matches(rule, file_type, file_hash, strings_list)
                
                if self.evaluate_condition(rule, matched_items):
                    risk_info = self.risk_levels.get(rule['priority'], 
                                                   {"name": "UNKNOWN", "color": Fore.WHITE, "symbol": "❓"})
                    
                    self.matches.append({
                        'json_file': os.path.basename(json_file),
                        'rule_name': rule['name'],
                        'file_type': file_type,
                        'file_hash': file_hash,
                        'matched_items': matched_items,
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'priority': rule['priority'],
                        'severity': rule['severity'],
                        'risk_info': risk_info
                    })
                    
        except Exception as e:
            print(f"파일 처리 오류 {json_file}: {e}")
    
    def scan_folder(self, folder_path):
        """폴더 스캔"""
        print(f"\n{Fore.CYAN}🔍 CAPE JSON 스캔 시작{Style.RESET_ALL}")
        print(f"📁 대상 폴더: {Fore.BLUE}{folder_path}{Style.RESET_ALL}")
        
        json_files = glob.glob(os.path.join(folder_path, "*.json"))
        print(f"📊 JSON 파일: {Fore.GREEN}{len(json_files)}개{Style.RESET_ALL} 발견\n")
        
        if not json_files:
            print(f"{Fore.RED}❌ JSON 파일을 찾을 수 없습니다!{Style.RESET_ALL}")
            return
        
        for i, json_file in enumerate(json_files, 1):
            file_name = os.path.basename(json_file)
            print(f"   {i:2d}. {file_name:<25}", end=" ")
            
            initial_match_count = len(self.matches)
            self.check_json_file(json_file)
            
            if len(self.matches) > initial_match_count:
                new_match = self.matches[-1]
                risk_info = new_match['risk_info']
                print(f"{risk_info['symbol']} {risk_info['color']}매치!{Style.RESET_ALL} → {Fore.YELLOW}{new_match['rule_name']}{Style.RESET_ALL}")
            else:
                print(f"✅ {Fore.GREEN}깨끗함{Style.RESET_ALL}")
        
        self.print_results()
    
    def print_results(self):
        """결과 출력 (기존 스타일 유지)"""
        print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📋 최종 스캔 결과{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
        
        if not self.matches:
            print(f"\n{Fore.GREEN}✅ 모든 파일이 안전합니다!{Style.RESET_ALL}")
            return
        
        # 통계
        unique_files = set(match['json_file'] for match in self.matches)
        risk_counts = {}
        for match in self.matches:
            severity = match['severity']
            risk_counts[severity] = risk_counts.get(severity, 0) + 1
        
        print(f"\n{Fore.RED}🚨 위험 탐지 결과{Style.RESET_ALL}")
        print(f"   ├── 감염된 파일: {Fore.RED}{len(unique_files)}개{Style.RESET_ALL}")
        print(f"   ├── 총 탐지 건수: {Fore.YELLOW}{len(self.matches)}개{Style.RESET_ALL}")
        print(f"   └── 위험도별 분포:")
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = risk_counts.get(severity, 0)
            if count > 0:
                color = Fore.RED if severity == 'CRITICAL' else \
                       Fore.YELLOW if severity == 'HIGH' else \
                       Fore.CYAN if severity == 'MEDIUM' else Fore.GREEN
                symbol = "🚨" if severity == 'CRITICAL' else "⚠️" if severity == 'HIGH' else "🔍"
                print(f"       └── {symbol} {color}{severity}: {count}개{Style.RESET_ALL}")
        
        # 상세 결과 (우선순위별)
        print(f"\n{Fore.CYAN}📋 상세 탐지 내역 (우선순위별){Style.RESET_ALL}")
        
        sorted_matches = sorted(self.matches, key=lambda x: (x['priority'], x['json_file']))
        
        current_priority = None
        for match in sorted_matches:
            if current_priority != match['priority']:
                current_priority = match['priority']
                risk_info = match['risk_info']
                print(f"\n{risk_info['symbol']} {risk_info['color']}[{risk_info['name']}] 우선순위 {current_priority}{Style.RESET_ALL}")
            
            print(f"   └── 📁 {match['json_file']}")
            print(f"       ├── 🎯 룰: {Fore.YELLOW}{match['rule_name']}{Style.RESET_ALL}")
            print(f"       ├── 📄 타입: {match['file_type'][:50]}{'...' if len(match['file_type']) > 50 else ''}")
            print(f"       ├── 🔑 해시: {match['file_hash'][:32]}...")
            print(f"       └── 🔍 매치:")
            
            for item in match['matched_items']:
                print(f"           └── {item}")

if __name__ == "__main__":
    # 간단한 배너
    print(f"\n{Fore.CYAN}╭─────────────────────────────────────────────╮")
    print(f"│{Style.BRIGHT}    🎯 CAPE Scanner Final Edition           {Style.RESET_ALL}{Fore.CYAN}│")
    print(f"╰─────────────────────────────────────────────╯{Style.RESET_ALL}")
    
    scanner = FinalCapeScanner("yara_rules_final.yar")
    
    folder_path = r"C:\Users\popo7\Desktop\yara_final\cape_reports"
    scanner.scan_folder(folder_path)
    
    print(f"\n{Fore.BLUE}스캔 완료! {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")