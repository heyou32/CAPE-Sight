from flask import Flask, render_template, request, jsonify, send_file
from cape_api import CAPEClient
import os, json, re
from datetime import datetime

app = Flask(__name__)
client = CAPEClient()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_FILE = os.path.join(BASE_DIR, 'rules', 'yara_rules.yar') 
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
UPLOADS_DIR = os.path.join(BASE_DIR, 'uploads')

for d in [REPORTS_DIR, UPLOADS_DIR]: os.makedirs(d, exist_ok=True)

def teammate_yara_scan(data):
    matches = []
    if not os.path.exists(RULES_FILE):
        print(f"⚠️ [경고] 룰 파일을 찾을 수 없습니다: {RULES_FILE}")
        return []

    with open(RULES_FILE, 'r', encoding='utf-8') as f:
        content = f.read()
    
    rule_blocks = re.findall(r'rule\s+(\w+)\s*\{([\s\S]*?)\}', content)
    
    target = data.get('target', {}).get('file', {})
    search_space = f"{target.get('type')} {target.get('sha256')} {' '.join(target.get('strings', []))}"
    for sig in data.get('signatures', []):
        search_space += f" {sig.get('name')} {sig.get('description')}"
    
    search_space = search_space.lower()

    for name, body in rule_blocks:
        matched_items = []
        patterns = re.findall(r'"([^"]*)"', body)
        for p in patterns:
            if p.lower() in search_space:
                if p.lower() in target.get('sha256', '').lower(): label = "Hash Match"
                elif p.lower() in target.get('type', '').lower(): label = "Type Match"
                else: label = "Behavior/String Match"
                matched_items.append(f"{label}: '{p}'")
        
        if matched_items:
            matches.append({
                "rule_name": name,
                "file_name": target.get('name', 'unknown'),
                "file_type": target.get('type', 'unknown'),
                "file_hash": target.get('sha256', 'unknown'),
                "matched_items": list(set(matched_items))
            })
    return matches

# IOC 추출 
def extract_iocs(data):
    network = data.get('network', {})
    return {
        'ips': list(set([c.get('dst') for p in ['tcp', 'udp'] for c in network.get(p, []) if c.get('dst')])),
        'urls': list(set([f"http://{h.get('host')}{h.get('uri')}" for h in network.get('http', []) if h.get('host')])),
        'domains': list(set([d.get('request') for d in network.get('dns', []) if d.get('request')])),
        'hashes': list(set([d.get('sha256') for d in data.get('dropped', []) if d.get('sha256')]))
    }

@app.route('/')
def index():
    yara_rules = []
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, 'r', encoding='utf-8') as f:
            yara_rules = re.findall(r'rule\s+([a-zA-Z0-9_]+)', f.read())
    return render_template('index.html', yara_rules=yara_rules)

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    path = os.path.join(UPLOADS_DIR, file.filename)
    file.save(path)
    return jsonify({"task_id": client.submit_files(path)})

@app.route('/status/<int:task_id>')
def get_status(task_id):
    return jsonify({"status": client.check_status(task_id)})

@app.route('/report/<int:task_id>')
def get_report(task_id):
    report_path = os.path.join(REPORTS_DIR, f"report_{task_id}.json")
    status = client.check_status(task_id)
    
    if client.make_report(task_id, report_path, status):
        with open(report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        data['yara_ioc'] = {
            'yara': teammate_yara_scan(data),
            'iocs': extract_iocs(data),
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
            
        return jsonify({"result": "success", "data": data})
    return jsonify({"result": "failed"})

@app.route('/download/<int:task_id>')
def download(task_id):
    path = os.path.join(REPORTS_DIR, f"CAPE-Sight_report_{task_id}.json")
    if os.path.exists(path):
        return send_file(path, as_attachment=True, download_name=f"CAPE_Analysis_{task_id}.json")
    return "파일 없음", 404

@app.route('/result_page/<int:task_id>')
def result_page(task_id):
    return render_template('result.html', task_id=task_id)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)