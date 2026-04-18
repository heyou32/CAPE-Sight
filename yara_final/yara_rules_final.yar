import "pe"

// ==========================================
// [CRITICAL] 즉시 격리 및 대응 필요
// ==========================================
rule Known_Malware_Hash {
    meta:
        description = "알려진 악성코드 해시 (즉시 격리 필요)"
        author = "CAPE Scanner Team"
        severity = "CRITICAL"
        priority = 1
        
    strings:
        $hash1 = "5646873f89e3468c306385ef3d65b7daf63aeee4128553c3224c75cb0e6902ca" ascii wide nocase
        $hash2 = "e2a24ab94f865caeacdf2c3ad015f31f23008ac6db8312c2cbfb32e4a5466ea2" ascii wide nocase
        $hash3 = "46713fa0caa7ad73ab2558456bdb0af41ed18e5c91d4622e4cbe998da501d45f" ascii wide nocase
        $hash4 = "d1ce31e807afee5b9e3ba6c63bd6b5f5c5c7b5f5" ascii wide nocase
        
    condition:
        any of ($hash*)
}

// ==========================================
// [HIGH] 시스템 심층 침해 및 능동적 공격
// ==========================================
rule Suspicious_PE_Executable {
    meta:
        description = "프로세스 인젝션을 사용하는 고위험 PE 파일"
        author = "CAPE Scanner Team"
        severity = "HIGH"
        priority = 2
        
    strings:
        $inject_api1 = "CreateRemoteThread" ascii wide
        $inject_api2 = "VirtualAllocEx" ascii wide
        $inject_api3 = "WriteProcessMemory" ascii wide
        $inject_api4 = "SetWindowsHookEx" ascii wide
        $inject_api5 = "QueueUserAPC" ascii wide
        
    condition:
        uint16(0) == 0x5a4d and 2 of ($inject_api*)
}

rule Theme_Specific_Campaign {
    meta:
        description = "확인된 특정 공격 캠페인 지표 (APT/Ransomware)"
        author = "CAPE Scanner Team"
        severity = "HIGH"
        priority = 3
        
    strings:
        $campaign1 = "Ontario1" ascii wide nocase
        $campaign2 = "id-qt-unotice" ascii wide nocase
        $campaign3 = "nCTg}9|" ascii wide
        $campaign4 = "vbGFZxv" ascii wide
        $campaign5 = "APT_String_2024" ascii wide nocase
        $campaign6 = "DARKSIDE_V2" ascii wide nocase
        
    condition:
        any of them
}

rule Malicious_BAT_Script {
    meta:
        description = "악성 배치 파일 및 스크립트 (우회 실행)"
        author = "CAPE Scanner Team"
        severity = "HIGH" 
        priority = 4
        
    strings:
        $bat_ext = ".bat" ascii wide nocase
        $cmd_exec = "cmd.exe" ascii wide nocase
        $powershell_exec = "powershell.exe" ascii wide nocase
        $pwsh_exec = "pwsh.exe" ascii wide nocase
        $bypass_policy = "-ExecutionPolicy Bypass" ascii wide nocase
        $hidden_window = "-WindowStyle Hidden" ascii wide nocase
        $encoded_cmd = "-EncodedCommand" ascii wide nocase
        $download_string = "DownloadString" ascii wide nocase
        
    condition:
        ($bat_ext or $cmd_exec) and 
        (any of ($powershell_exec, $pwsh_exec) and 
         any of ($bypass_policy, $hidden_window, $encoded_cmd, $download_string))
}

rule File_Extension_Masquerading {
    meta:
        description = "파일 확장자 이중 위장 기법 (RTLO 기법 등 포함)"
        author = "CAPE Scanner Team"
        severity = "HIGH"
        priority = 5
        
    strings:
        $fake_doc = /\.doc\.exe$/i
        $fake_pdf = /\.pdf\.exe$/i
        $fake_jpg = /\.jpg\.exe$/i
        $fake_txt = /\.txt\.exe$/i
        $fake_zip = /\.zip\.exe$/i
        $rlo = { E2 80 AE }
        
    condition:
        any of ($fake_*) or $rlo
}

// ==========================================
// [MEDIUM] 초기 침투 벡터 및 스크립트
// ==========================================
rule Malicious_LNK_File {
    meta:
        description = "악성 바로가기 파일 (초기 침투)"
        author = "CAPE Scanner Team"
        severity = "MEDIUM"
        priority = 6
        
    strings:
        $mshta_exe = "mshta.exe" ascii wide nocase
        $powershell = "powershell.exe" ascii wide nocase
        $cmd_exe = "cmd.exe" ascii wide nocase
        $suspicious_args = "command line arguments" ascii wide nocase
        $bypass_flag = "-ExecutionPolicy Bypass" ascii wide nocase
        
    condition:
        uint32(0) == 0x0000004c and 
        (any of ($mshta_exe, $powershell, $cmd_exe) and 
         any of ($suspicious_args, $bypass_flag))
}

rule Theme_JS_Malware {
    meta:
        description = "웹 기반 자바스크립트 공격 패턴 (난독화/다운로더)"
        author = "CAPE Scanner Team"
        severity = "MEDIUM"
        priority = 7
        
    strings:
        $js_ext = ".js" ascii wide nocase
        $js_type = "JavaScript" ascii wide nocase
        $wscript = "WScript.Shell" ascii wide nocase
        $activex = "ActiveXObject" ascii wide nocase
        $eval_func = "eval(" ascii wide nocase
        $unescape = "unescape" ascii wide nocase
        $fromcharcode = "String.fromCharCode" ascii wide nocase
        $long_lines = "very long lines" ascii wide nocase
        
    condition:
        ($js_ext or $js_type) and 
        (2 of ($wscript, $activex) or 
         ($wscript and any of ($eval_func, $unescape, $fromcharcode))) and 
        $long_lines
}

rule Suspicious_Encrypted_Archive {
    meta:
        description = "암호화된 압축파일 (샌드박스 우회용)"
        author = "CAPE Scanner Team"
        severity = "MEDIUM"
        priority = 8
        
    strings:
        $aes_encrypted = "AES Encrypted" ascii wide nocase
        $password_protected = "password protected" ascii wide nocase
        $encrypted = "encrypted" ascii wide nocase
        
    condition:
        (uint32(0) == 0x04034b50 or uint32(0) == 0x21726152 or uint32(0) == 0x377abcaf) and 
        any of them
}

rule Malicious_PDF {
    meta:
        description = "악성 PDF 문서 (JS 삽입 및 자동 실행)"
        author = "CAPE Scanner Team"
        severity = "MEDIUM"
        priority = 9
        
    strings:
        $js_embed = "/JavaScript" ascii wide
        $js_embed2 = "/JS" ascii wide
        $openaction = "/OpenAction" ascii wide
        $launch = "/Launch" ascii wide
        $flatedecode = "FlateDecode" ascii wide
        
    condition:
        uint32(0) == 0x46445025 and 
        (2 of ($js_embed, $js_embed2, $openaction, $launch) or 
         ($openaction and $flatedecode))
}

rule Suspicious_Unicode_Script {
    meta:
        description = "의심스러운 유니코드 스크립트 (파워쉘 우회 공격)"
        author = "CAPE Scanner Team"
        severity = "MEDIUM"
        priority = 10
        
    strings:
        $utf16_le_bom = { FF FE }
        $utf16_be_bom = { FE FF }
        $very_long = "very long lines" ascii wide
        $powershell_bypass = "-EncodedCommand" ascii wide nocase
        $execution_policy = "executionpolicy" ascii wide nocase
        
    condition:
        ($utf16_le_bom at 0 or $utf16_be_bom at 0) and 
        ($very_long or $powershell_bypass or $execution_policy)
}