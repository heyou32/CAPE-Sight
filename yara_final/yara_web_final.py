from flask import Flask, jsonify
import json
import os
import glob
import re
from datetime import datetime
from threading import Thread
import time

app = Flask(__name__)

class SimpleWebScanner:
    def __init__(self, rules_file="yara_rules_final.yar"):
        self.rules = []
        self.matches = []
        self.scan_status = {
            'running': False,
            'progress': 0,
            'current': 0,
            'total': 0,
            'current_file': ''
        }
        self.load_rules(rules_file)
    
    def load_rules(self, rules_file):
        """간단한 룰 로드"""
        try:
            with open(rules_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            rule_blocks = re.findall(r'rule\s+(\w+)\s*\{(.*?)\n\}', content, re.DOTALL)
            
            for rule_name, rule_content in rule_blocks:
                priority = 99
                severity = "UNKNOWN"
                
                meta_match = re.search(r'priority\s*=\s*(\d+)', rule_content)
                severity_match = re.search(r'severity\s*=\s*"(\w+)"', rule_content)
                
                if meta_match:
                    priority = int(meta_match.group(1))
                if severity_match:
                    severity = severity_match.group(1)
                
                strings = []
                strings_match = re.search(r'strings:(.*?)condition:', rule_content, re.DOTALL)
                
                if strings_match:
                    for line in strings_match.group(1).split('\n'):
                        if '$' in line and '=' in line:
                            var_name = line.strip().split('=')[0].strip()
                            string_value = re.findall(r'"([^"]*)"', line)
                            if string_value:
                                strings.append((var_name, string_value[0]))
                
                condition_match = re.search(r'condition:\s*(.*)', rule_content, re.DOTALL)
                condition = condition_match.group(1).strip() if condition_match else ""
                
                self.rules.append({
                    'name': rule_name,
                    'strings': strings,
                    'condition': condition,
                    'priority': priority,
                    'severity': severity
                })
            
            self.rules.sort(key=lambda x: x['priority'])
            
        except Exception as e:
            print(f"룰 로딩 오류: {e}")
    
    def get_matches(self, rule, file_type, file_hash, strings_list):
        """패턴 매칭"""
        matches = []
        
        for var_name, pattern in rule['strings']:
            if pattern.lower() in file_hash.lower():
                matches.append(f"{var_name}: '{pattern}' (hash)")
                continue
            
            if pattern.lower() in file_type.lower():
                matches.append(f"{var_name}: '{pattern}' (filetype)")
                continue
            
            for s in strings_list:
                if pattern.lower() in s.lower():
                    matches.append(f"{var_name}: '{pattern}' (strings)")
                    break
        
        return matches
    
    def evaluate_condition(self, rule, matched_items):
        """조건 평가"""
        condition = rule['condition'].lower()
        match_count = len(matched_items)
        
        if rule['name'] == 'Known_Malware_Hash':
            return match_count > 0
        
        if 'any of them' in condition or 'any of ($' in condition:
            return match_count > 0
        elif '2 of' in condition:
            return match_count >= 2
        elif 'and' in condition:
            return match_count >= 2 if 'any of' not in condition else match_count > 0
        else:
            return match_count > 0
    
    def check_json_file(self, json_file):
        """JSON 파일 검사"""
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
                    self.matches.append({
                        'json_file': os.path.basename(json_file),
                        'rule_name': rule['name'],
                        'file_type': file_type,
                        'file_hash': file_hash,
                        'matched_items': matched_items,
                        'priority': rule['priority'],
                        'severity': rule['severity'],
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    })
                    
        except Exception as e:
            print(f"파일 처리 오류: {e}")
    
    def scan_folder_async(self, folder_path):
        """비동기 스캔"""
        self.matches = []
        self.scan_status['running'] = True
        
        json_files = glob.glob(os.path.join(folder_path, "*.json"))
        self.scan_status['total'] = len(json_files)
        
        for i, json_file in enumerate(json_files, 1):
            self.scan_status['current'] = i
            self.scan_status['current_file'] = os.path.basename(json_file)
            self.scan_status['progress'] = int((i / len(json_files)) * 100)
            
            self.check_json_file(json_file)
            time.sleep(0.1)
        
        self.scan_status['running'] = False

# 전역 스캐너
scanner = SimpleWebScanner()

@app.route('/')
def index():
    """메인 페이지 (위협 파일 목록 추가)"""
    return f"""
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <title>🎯 CAPE Scanner Web</title>
        <style>
            body {{ 
                font-family: Arial, sans-serif; 
                max-width: 1200px; 
                margin: 0 auto; 
                padding: 20px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                min-height: 100vh;
            }}
            .container {{ 
                background: rgba(255,255,255,0.1); 
                padding: 30px; 
                border-radius: 15px; 
                backdrop-filter: blur(10px);
            }}
            h1 {{ text-align: center; margin-bottom: 30px; }}
            .stats {{ 
                display: grid; 
                grid-template-columns: repeat(4, 1fr); 
                gap: 20px; 
                margin-bottom: 30px; 
            }}
            .stat-card {{ 
                background: rgba(255,255,255,0.2); 
                padding: 20px; 
                border-radius: 10px; 
                text-align: center; 
            }}
            .stat-value {{ font-size: 2em; font-weight: bold; margin-bottom: 10px; }}
            .btn {{ 
                background: linear-gradient(45deg, #ff6b6b, #ee5a24);
                border: none; 
                padding: 15px 30px; 
                border-radius: 25px; 
                color: white; 
                font-size: 16px; 
                cursor: pointer; 
                margin: 10px;
                transition: all 0.3s;
            }}
            .btn:hover {{ transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.3); }}
            .btn:disabled {{ background: #666; cursor: not-allowed; }}
            .progress {{ 
                width: 100%; 
                height: 20px; 
                background: rgba(255,255,255,0.2); 
                border-radius: 10px; 
                overflow: hidden;
                margin: 20px 0;
                display: none;
            }}
            .progress-bar {{ 
                height: 100%; 
                background: linear-gradient(45deg, #4ecdc4, #44a08d); 
                width: 0%; 
                transition: width 0.3s; 
            }}
            
            /* 위협 파일 목록 스타일 */
            .threat-files-section {{
                display: none;
                margin-top: 20px;
            }}
            .threat-files-container {{
                display: grid;
                grid-template-columns: 1fr 2fr;
                gap: 20px;
            }}
            .threat-files-list {{
                background: rgba(255,107,107,0.2);
                border-radius: 10px;
                padding: 20px;
                border-left: 5px solid #ff6b6b;
                max-height: 400px;
                overflow-y: auto;
            }}
            .threat-file-item {{
                background: rgba(255,255,255,0.1);
                padding: 12px;
                margin: 8px 0;
                border-radius: 8px;
                cursor: pointer;
                transition: all 0.3s;
                border-left: 4px solid transparent;
            }}
            .threat-file-item:hover {{
                background: rgba(255,255,255,0.2);
                transform: translateX(5px);
            }}
            .threat-file-item.critical {{
                border-left-color: #ff6b6b;
            }}
            .threat-file-item.high {{
                border-left-color: #ffa726;
            }}
            .threat-file-item.medium {{
                border-left-color: #42a5f5;
            }}
            .threat-file-name {{
                font-weight: bold;
                font-size: 14px;
            }}
            .threat-file-info {{
                font-size: 12px;
                opacity: 0.8;
                margin-top: 5px;
            }}
            
            /* 파일 상세 정보 */
            .file-detail-panel {{
                background: rgba(255,255,255,0.1);
                border-radius: 10px;
                padding: 20px;
                border: 2px solid rgba(255,255,255,0.2);
            }}
            .detail-empty {{
                text-align: center;
                color: rgba(255,255,255,0.6);
                padding: 60px 20px;
            }}
            
            .results {{ 
                background: rgba(255,255,255,0.1); 
                padding: 20px; 
                border-radius: 10px; 
                margin-top: 20px; 
                max-height: 500px;
                overflow-y: auto;
                display: none;
            }}
            .threat {{ 
                background: rgba(255,107,107,0.3); 
                padding: 15px; 
                margin: 10px 0; 
                border-radius: 8px; 
                border-left: 4px solid #ff6b6b; 
            }}
            .safe {{ 
                text-align: center; 
                font-size: 1.2em; 
                color: #4ecdc4; 
                padding: 40px; 
            }}
            .loading {{ 
                display: inline-block; 
                width: 20px; 
                height: 20px; 
                border: 3px solid rgba(255,255,255,0.3); 
                border-radius: 50%; 
                border-top-color: #fff; 
                animation: spin 1s ease-in-out infinite; 
            }}
            @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
            
            .priority-badge {{
                padding: 2px 8px;
                border-radius: 12px;
                font-size: 10px;
                font-weight: bold;
            }}
            .priority-critical {{ background: #ff6b6b; }}
            .priority-high {{ background: #ffa726; }}
            .priority-medium {{ background: #42a5f5; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🎯 CAPE Scanner Web Final</h1>
            
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-value" id="totalRules">{len(scanner.rules)}</div>
                    <div>활성 룰</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="totalFiles">-</div>
                    <div>총 파일</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="scannedFiles">-</div>
                    <div>스캔 완료</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="threatsFound">-</div>
                    <div>위협 탐지</div>
                </div>
            </div>
            
            <div style="text-align: center;">
                <button id="scanBtn" class="btn" onclick="startScan()">🚀 스캔 시작</button>
                <button class="btn" onclick="showRules()" style="background: linear-gradient(45deg, #4ecdc4, #44a08d);">📋 룰 정보</button>
                <button class="btn" onclick="toggleThreatFiles()" style="background: linear-gradient(45deg, #e74c3c, #c0392b); display: none;" id="threatFilesBtn">🚨 위험 파일 목록</button>
            </div>
            
            <div class="progress" id="progressContainer">
                <div class="progress-bar" id="progressBar"></div>
                <div id="progressText" style="text-align: center; margin-top: 10px;"></div>
            </div>
            
            <!-- 위험 파일 목록 섹션 (새로 추가) -->
            <div class="threat-files-section" id="threatFilesSection">
                <h3>🚨 위험 파일 목록</h3>
                <div class="threat-files-container">
                    <div class="threat-files-list">
                        <h4 style="margin-top: 0;">📁 탐지된 파일들</h4>
                        <div id="threatFilesList">
                            <!-- 위험 파일 목록이 여기에 표시됩니다 -->
                        </div>
                    </div>
                    <div class="file-detail-panel">
                        <div id="fileDetailContent" class="detail-empty">
                            <i style="font-size: 48px; opacity: 0.3;">📄</i>
                            <p>파일을 선택하면 상세 정보가 표시됩니다</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="results" id="results"></div>
        </div>

        <script>
            let scanInterval;
            let currentMatches = [];

            function startScan() {{
                const scanBtn = document.getElementById('scanBtn');
                const progressContainer = document.getElementById('progressContainer');
                const results = document.getElementById('results');
                const threatFilesSection = document.getElementById('threatFilesSection');
                const threatFilesBtn = document.getElementById('threatFilesBtn');
                
                scanBtn.disabled = true;
                scanBtn.innerHTML = '<span class="loading"></span> 스캔 중...';
                progressContainer.style.display = 'block';
                results.style.display = 'none';
                threatFilesSection.style.display = 'none';
                threatFilesBtn.style.display = 'none';
                
                fetch('/start_scan', {{method: 'POST'}})
                    .then(response => response.json())
                    .then(data => {{
                        if (data.status === 'started') {{
                            scanInterval = setInterval(updateProgress, 500);
                        }}
                    }});
            }}

            function updateProgress() {{
                fetch('/scan_status')
                    .then(response => response.json())
                    .then(data => {{
                        const progressBar = document.getElementById('progressBar');
                        const progressText = document.getElementById('progressText');
                        const totalFiles = document.getElementById('totalFiles');
                        const scannedFiles = document.getElementById('scannedFiles');
                        
                        progressBar.style.width = data.progress + '%';
                        progressText.textContent = `${{data.current}}/${{data.total}} - ${{data.current_file}}`;
                        totalFiles.textContent = data.total;
                        scannedFiles.textContent = data.current;
                        
                        if (!data.running) {{
                            clearInterval(scanInterval);
                            loadResults();
                            
                            const scanBtn = document.getElementById('scanBtn');
                            scanBtn.disabled = false;
                            scanBtn.innerHTML = '🚀 스캔 시작';
                            progressText.textContent = '스캔 완료!';
                        }}
                    }});
            }}

            function loadResults() {{
                fetch('/scan_results')
                    .then(response => response.json())
                    .then(data => {{
                        currentMatches = data.matches;
                        const results = document.getElementById('results');
                        const threatsFound = document.getElementById('threatsFound');
                        const threatFilesBtn = document.getElementById('threatFilesBtn');
                        
                        threatsFound.textContent = data.total_matches;
                        results.style.display = 'block';
                        
                        if (data.total_matches === 0) {{
                            results.innerHTML = '<div class="safe">✅ 안전합니다!<br>위협이 탐지되지 않았습니다.</div>';
                        }} else {{
                            // 위험 파일 목록 버튼 표시
                            threatFilesBtn.style.display = 'inline-block';
                            
                            let html = `<h3>🚨 ${{data.total_matches}}개 위협 탐지</h3>`;
                            html += '<p style="text-align: center; margin: 20px 0;"><button class="btn" onclick="toggleThreatFiles()" style="background: linear-gradient(45deg, #e74c3c, #c0392b);">📁 위험 파일 목록 보기</button></p>';
                            
                            results.innerHTML = html;
                            
                            // 위험 파일 목록 생성
                            generateThreatFilesList(data.matches);
                        }}
                    }});
            }}

            function generateThreatFilesList(matches) {{
                const threatFilesList = document.getElementById('threatFilesList');
                
                // 파일별로 그룹화
                const fileGroups = {{}};
                matches.forEach(match => {{
                    const fileName = match.json_file;
                    if (!fileGroups[fileName]) {{
                        fileGroups[fileName] = [];
                    }}
                    fileGroups[fileName].push(match);
                }});
                
                // 우선순위별로 정렬
                const sortedFiles = Object.entries(fileGroups).sort((a, b) => {{
                    const minPriorityA = Math.min(...a[1].map(m => m.priority));
                    const minPriorityB = Math.min(...b[1].map(m => m.priority));
                    return minPriorityA - minPriorityB;
                }});
                
                let html = '';
                sortedFiles.forEach(([fileName, fileMatches]) => {{
                    const maxPriority = Math.min(...fileMatches.map(m => m.priority));
                    const maxSeverity = fileMatches.find(m => m.priority === maxPriority).severity;
                    
                    const severityClass = maxSeverity.toLowerCase();
                    const severityIcon = maxSeverity === 'CRITICAL' ? '🚨' : 
                                       maxSeverity === 'HIGH' ? '⚠️' : '🔍';
                    
                    html += `
                        <div class="threat-file-item ${{severityClass}}" onclick="showFileDetail('${{fileName}}')">
                            <div class="threat-file-name">
                                ${{severityIcon}} ${{fileName}}
                                <span class="priority-badge priority-${{severityClass}}">${{maxSeverity}}</span>
                            </div>
                            <div class="threat-file-info">
                                ${{fileMatches.length}}개 룰 매치 | 우선순위 ${{maxPriority}}
                            </div>
                        </div>
                    `;
                }});
                
                threatFilesList.innerHTML = html;
            }}

            function showFileDetail(fileName) {{
                const fileDetailContent = document.getElementById('fileDetailContent');
                const fileMatches = currentMatches.filter(m => m.json_file === fileName);
                
                if (fileMatches.length === 0) return;
                
                const firstMatch = fileMatches[0];
                
                let html = `
                    <h4>📄 ${{fileName}}</h4>
                    <div style="margin: 15px 0; padding: 15px; background: rgba(0,0,0,0.2); border-radius: 8px;">
                        <p><strong>🔍 파일 타입:</strong><br>${{firstMatch.file_type.substring(0, 80)}}...</p>
                        <p><strong>🔐 SHA256 해시:</strong><br><code style="word-break: break-all; font-size: 11px;">${{firstMatch.file_hash}}</code></p>
                        <p><strong>⏰ 탐지 시간:</strong> ${{firstMatch.timestamp}}</p>
                    </div>
                    
                    <h5>🎯 탐지된 룰들 (${{fileMatches.length}}개)</h5>
                `;
                
                fileMatches.forEach(match => {{
                    const priorityClass = match.severity.toLowerCase();
                    const priorityIcon = match.severity === 'CRITICAL' ? '🚨' : 
                                       match.severity === 'HIGH' ? '⚠️' : '🔍';
                    
                    html += `
                        <div style="margin: 10px 0; padding: 12px; background: rgba(255,255,255,0.1); border-radius: 6px; border-left: 3px solid var(--${{priorityClass}}-color, #42a5f5);">
                            <strong>${{priorityIcon}} ${{match.rule_name}}</strong>
                            <span class="priority-badge priority-${{priorityClass}}" style="float: right;">${{match.severity}}</span>
                            <div style="margin-top: 8px; font-size: 13px;">
                                <strong>매치된 패턴:</strong>
                                <ul style="margin: 5px 0; padding-left: 20px;">
                                    ${{match.matched_items.map(item => `<li>${{item}}</li>`).join('')}}
                                </ul>
                            </div>
                        </div>
                    `;
                }});
                
                fileDetailContent.innerHTML = html;
            }}

            function toggleThreatFiles() {{
                const section = document.getElementById('threatFilesSection');
                const isVisible = section.style.display !== 'none';
                section.style.display = isVisible ? 'none' : 'block';
                
                if (!isVisible) {{
                    section.scrollIntoView({{ behavior: 'smooth' }});
                }}
            }}

            function showRules() {{
                const results = document.getElementById('results');
                const threatFilesSection = document.getElementById('threatFilesSection');
                
                results.style.display = 'block';
                threatFilesSection.style.display = 'none';
                
                let html = `<h3>📋 활성화된 YARA 룰 (${{document.getElementById('totalRules').textContent}}개)</h3>`;
                
                fetch('/rules_info')
                    .then(response => response.json())
                    .then(data => {{
                        data.rules.forEach(rule => {{
                            const priorityColor = rule.priority == 1 ? '#ff6b6b' :
                                                rule.priority <= 5 ? '#ffa726' : '#42a5f5';
                            
                            html += `
                                <div style="background: rgba(255,255,255,0.1); padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid ${{priorityColor}};">
                                    <h4>${{rule.name}} [${{rule.severity}}]</h4>
                                    <p><strong>우선순위:</strong> ${{rule.priority}}</p>
                                    <p><strong>문자열 패턴:</strong> ${{rule.strings_count}}개</p>
                                    <p><strong>조건:</strong> ${{rule.condition.substring(0, 100)}}...</p>
                                </div>
                            `;
                        }});
                        
                        results.innerHTML = html;
                    }});
            }}
        </script>
    </body>
    </html>
    """

@app.route('/start_scan', methods=['POST'])
def start_scan():
    """스캔 시작"""
    if scanner.scan_status['running']:
        return jsonify({'status': 'already_running'})
    
    folder_path = r"C:\Users\popo7\Desktop\yara_final\cape_reports"
    
    thread = Thread(target=scanner.scan_folder_async, args=(folder_path,))
    thread.daemon = True
    thread.start()
    
    return jsonify({'status': 'started'})

@app.route('/scan_status')
def scan_status():
    """스캔 상태"""
    return jsonify(scanner.scan_status)

@app.route('/scan_results')
def scan_results():
    """스캔 결과"""
    return jsonify({
        'total_matches': len(scanner.matches),
        'matches': scanner.matches
    })

@app.route('/rules_info')
def rules_info():
    """룰 정보"""
    rules_data = []
    for rule in scanner.rules:
        rules_data.append({
            'name': rule['name'],
            'priority': rule['priority'],
            'severity': rule['severity'],
            'strings_count': len(rule['strings']),
            'condition': rule['condition']
        })
    
    return jsonify({
        'total_rules': len(scanner.rules),
        'rules': rules_data
    })

if __name__ == '__main__':
    print("🌐 CAPE Scanner Web Final 시작...")
    print("📍 http://localhost:5000")
    print(f"📋 로드된 룰: {len(scanner.rules)}개")
    
    app.run(debug=True, port=5000)
