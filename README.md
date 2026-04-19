# Cape IOC Analyzer

CAPE 샌드박스 분석 결과에서 IOC(Indicators of Compromise)를 추출하고 분석하는 도구입니다.

## 🔧 주요 기능

- **IOC 추출**: CAPE 분석 결과에서 악성 지표 추출
- **PE 파일 분석**: 실행 파일의 메타데이터 및 의심스러운 특성 분석
- **배치 처리**: 다수 샘플의 일괄 분석
- **보고서 생성**: 분석 결과의 종합적인 리포트 생성

## 📁 프로젝트 구조
```
ioc_report/
├── main.py                 # 메인 실행 파일
├── cape_analyzer/          # 핵심 분석 모듈
│   ├── analyzer.py         # 메인 분석기
│   ├── ioc_extractor.py    # IOC 추출기
│   ├── pe_analyzer.py      # PE 파일 분석기
│   ├── report_generator.py # 보고서 생성기
│   └── utils.py           # 유틸리티 함수
├── config/                 # 설정 파일
├── batch_output/          # 배치 처리 결과
└── cape_results/          # CAPE 분석 결과 샘플
```


## 🚀 사용법

```bash
# 메인 분석 실행
python main.py

# 개별 모듈 사용 예시
from cape_analyzer import analyzer, ioc_extractor
