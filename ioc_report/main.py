"""
CAPE 배치 분석기 메인 실행 파일
"""
from cape_analyzer import BatchCapeAnalyzer
from config.settings import DEFAULT_INPUT_FOLDER, DEFAULT_OUTPUT_FOLDER

def main():
    print("🔍 CAPE 배치 분석 시스템 v1.0")
    print("=" * 50)
    
    # 사용자 입력 또는 기본값 사용
    input_folder = input(f"JSON 파일들이 있는 폴더명 (기본: {DEFAULT_INPUT_FOLDER}): ").strip()
    if not input_folder:
        input_folder = DEFAULT_INPUT_FOLDER
    
    output_folder = input(f"결과 저장할 폴더명 (기본: {DEFAULT_OUTPUT_FOLDER}): ").strip()
    if not output_folder:
        output_folder = DEFAULT_OUTPUT_FOLDER
    
    # 분석 실행
    analyzer = BatchCapeAnalyzer(input_folder, output_folder)
    analyzer.run_batch_analysis()
    
    input("\n✨ 엔터를 눌러서 종료...")

if __name__ == "__main__":
    main()