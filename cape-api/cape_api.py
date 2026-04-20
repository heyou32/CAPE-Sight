import requests
import os
import json
import time
import utils

class CAPEClient:
    def __init__(self, url="http://192.168.243.129:8000/apiv2"): # api 전용 주소
        if not url.endswith('/'):
            url += '/'
        self.url = url
        self.headers = {'Accept': 'application/json'}
        
    # ping 테스트용
    def ping_server(self, onCape = True):
        # cape 사용
        if onCape:
            endpoint = f"{self.url}cuckoo/status"            
            try:
                response=requests.get(endpoint)
                if response.status_code==200:
                    print("연결 성공")
                    return response.json()
                else :
                    print(f"연결 실패 : {response.status_code}")
                    return None
            except requests.exceptions.ConnectionError:
                print(f"서버 응답 없음.")
                return None 

            # 로컬 테스트용
            else:
                return
    def submit_files(self, filepath):
        endpoint = f"{self.url}tasks/create/file/"
        if not os.path.exists(filepath):
            print(f"파일을 찾을 수 없습니다: {filepath}")
            return None
        
        try:
            with open(filepath, 'rb') as f:
                files = {'file': (os.path.basename(filepath),f)}
                # 파일 전송 시에는 headers에서 Accept만 유지, Content-Type은 requests가 알아서 잡게 둠
                response=requests.post(endpoint,files=files,headers=self.headers)
                
            res_json=response.json()    
            if response.status_code==200:
                if res_json.get('error'):
                    print(f"{res_json.get('error_value')}")
                    print(f"{res_json.get('errors')}")
                    return None
                
                task_ids = res_json.get("data", {}).get("task_ids", [])
                if task_ids  :
                    task_id = task_ids[0]
                    print(f"업로드 완료 : {task_id} ")
                    return task_id
                else:
                    print(res_json)
                    print('task 생성 실패')
                    return None
            else:
                print(f"업로드 실패: {response.status_code}")
        except Exception as e:
            print(f"파일 전송 중 에러: {e}")
        
    # 분석 끝났는지 확인
    def check_status(self,task_id):
        endpoint = f"{self.url}tasks/view/{task_id}/"
        response = requests.get(endpoint,headers=self.headers)
        if response.status_code==200:
            staus = response.json().get("data",{}).get("status")
            return staus
        else:
            print(f"실패:{response.status_code}")
            return None
    
    # 리포트 가져오기(json 그대로)
    def get_report(self, task_id, output_path):
        endpoint=f"{self.url}tasks/get/report/{task_id}/json/"
        
        print(f"리포트 요청중... : {task_id}")
        response = requests.get(endpoint,headers=self.headers, stream=True)
        
        if response.status_code==200:
            # 대용량 파일 다운 (스트리밍 방식)
            with open(output_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=10*1024):
                    f.write(chunk)                
            print("-> 성공")
            return True
        else:
            print(f"-> 실패:{response.status_code}")
            return None
        
    # 수동 리포트 생성
    def make_report(self, task_id,output_filename, status):
        command = ["poetry", "run", "python3", "utils/process.py", "-r", str(task_id)]
        if utils.run_command(command) :
            print('리포트 생성 중 에러 발생')
            if self.get_report(task_id,output_filename) or status == 'reported':
                print('\n리포트 저장 중...')
                file_size = os.path.getsize(output_filename) / (1024 * 1024)
                print(f'리포트를 저장했습니다. ({file_size:.2f})MB')
                return True
            else:
                print('리포트 저장 실패')
                return None
            
if __name__== "__main__":
    
    client = CAPEClient()
    
    print("cape 서버 접속 시도중...")    
    result=client.ping_server();
    if not result: 
        print("프로그램을 종료합니다.")
        exit()
    
    
    # vm 켜져 있는지 확인
    vm = result.get('data', {}).get('machines', [])
    # if not [m for m in vm if m.get('status') != 'poweroff'] :
    if len(vm) == 0:
        print('사용가능한 가상머신이 없습니다.')
        print("프로그램을 종료합니다.")
        exit()
        
        
    # 업로드한 파일로 수정   
    target_file = "/home/hey/Downloads/test.txt"
    data=result.get('data',result)
    print(f"업로드 중:{target_file}")

    task_id = client.submit_files(target_file)
    if task_id:
        print(f'[task id:{task_id}] 분석 요청 중...')
    else:
        print('요청 할 수 없습니다. cape 웹 서버의 상태를 확인하세요')
        exit()

    # 분석, 저장 완료될 때까지 상태를 확인
    while True:
        cur_status = client.check_status(task_id)
        print(f"    -> 현재 상태 {cur_status}")
        
        if cur_status=="reported" or cur_status=="completed":
            print('     분석 완료!')
            print('리포트 생성 중...')
            output_filename = f"./report_{task_id}.json"
            client.make_report(task_id,output_filename,cur_status)                    
            break                
        elif cur_status=="pending":
            print('     분석 대기 중')
        elif cur_status=="running":
            print('     분석 중')
        elif cur_status in ['failed', 'error',"failed_analysis"]:
            print('     분석 실패 : '+data.get('error_value', None))
            exit()
        
        time.sleep(60)
