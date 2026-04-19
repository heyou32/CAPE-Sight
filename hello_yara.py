import yara
import os
import time

print("=" * 65)
print(" 🚨 [고급] 악성코드 정적 분석 스캐너 (YARA Engine) 🚨")
print("=" * 65)

# 1. 수배서(YARA 룰) 불러오기
try:
    rules = yara.compile(filepath='malware.yar')
    print("[+] 멀웨어(malware.yar) 로드 완벽하게 성공!\n")
except Exception as e:
    print(f"[-] 🚨 멀웨어 로드 실패 (문법 오류를 확인하세요): {e}")
    exit()

# 2. 스캔할 폴더 지정
folder_path = './yara'
scan_count = 0
detect_count = 0

print(f"[*] '{folder_path}' 폴더 내의 모든 파일 스캔을 시작합니다...")
print("-" * 65)

# 3. 하위 폴더까지 싹 다 뒤져서 파일 검사 (os.walk 사용)
for root, dirs, files in os.walk(folder_path):
    for filename in files:
        target_file = os.path.join(root, filename)
        scan_count += 1
        
        try:
            # YARA 스캔 진행
            matches = rules.match(target_file)
            
            # 탐지된 놈들만 화면에 아주 상세하게 출력
            if matches:
                detect_count += 1
                print(f"💥 [범인 발견] 의심 파일: {target_file}")
                
                # 걸려든 룰이 여러 개일 수 있으니 하나씩 뽑아서 출력
                for match in matches:
                    # YARA 룰에 적어둔 meta 정보(위험도, 설명 등)를 가져옴
                    severity = match.meta.get('severity', '분류 안됨')
                    desc = match.meta.get('description', '설명 없음')
                    
                    print(f"   ㄴ 🛑 [탐지 룰] {match.rule}")
                    print(f"   ㄴ ⚠️ [위험도] {severity}")
                    print(f"   ㄴ 📋 [상세설명] {desc}")
                print("-" * 65)
                
        except Exception as e:
            # 권한이 없거나 깨진 파일이 있을 때 프로그램이 안 뻗게 예외 처리
            print(f"[-] 파일 스캔 오류 건너뜀 ({filename}): {e}")

# 4. 스캔 완료 후 통계 요약 리포트
print("=" * 65)
print(" 🏁 스캔 결과 요약 리포트")
print("=" * 65)
print(f" - 총 검사한 파일 수 : {scan_count} 개")
print(f" - 악성 탐지 파일 수 : {detect_count} 개")

if detect_count > 0:
    print("\n🚨 [경고] 악성코드가 발견되었습니다. 즉시 격리 조치하시기 바랍니다.")
else:
    print("\n✅ [안전] 탐지된 악성코드가 없습니다. 깨끗합니다.")
print("=" * 65)