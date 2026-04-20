import subprocess
import os

CAPE_DIR = "/opt/CAPEv2"

# 명령어 실행
def run_command(cmd):
    try:
        # 실행 중인 Poetry 환경 변수를 제거하여 충돌 방지
        clean_env = os.environ.copy()
        clean_env.pop("VIRTUAL_ENV", None)
        clean_env.pop("POETRY_ACTIVE", None)

        subprocess.run(cmd, cwd=CAPE_DIR, env=clean_env, check=True, capture_output=True)
        print(f"[{cmd[3]}] 실행 완료!")
        return True
        
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode('utf-8', errors='ignore') if e.stderr else "에러 내용 없음"
        
        print("리포트 생성 중 에러 발생!")
        print(error_msg) 
        return False