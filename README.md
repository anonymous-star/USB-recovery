# USB Recovery Tool (USB 복구 도구)

손상된 USB 드라이브에서 파일을 복구하는 Python 도구입니다.

## 주요 기능

- **장치 감지**: 연결된 USB/저장 장치 목록 확인
- **디스크 이미지 생성**: 복구 작업 전 USB 전체 백업 (권장)
- **파일 시그니처 기반 복구 (File Carving)**: 30+ 파일 형식의 매직 바이트를 이용한 원시 복구
- **디렉토리 기반 복구**: 마운트된 USB에서 접근 가능한 파일 복사
- **파일시스템 복구**: FAT/NTFS/ext 파일시스템 자동 복구 시도

## 지원 파일 형식

| 카테고리 | 형식 |
|---------|------|
| 이미지 | JPG, PNG, GIF, BMP, ICO, WebP, TIFF |
| 문서 | PDF, DOC/DOCX, XLS/XLSX, PPT/PPTX, HWP/HWPX (한글), ODT |
| 오디오 | MP3, FLAC, OGG |
| 비디오 | MP4, MKV/WebM |
| 압축 | ZIP, RAR, 7Z, GZ, XZ, BZ2 |
| 기타 | ELF, EXE, HTML, XML, SQLite |

## 요구사항

- Python 3.6 이상
- Linux/macOS/Windows 지원
- 장치 직접 접근 시 root/관리자 권한 필요

## 사용법

### 대화형 모드 (권장)

```bash
sudo python3 usb_recovery.py
```

### 명령행 모드

```bash
# 연결된 장치 목록 보기
sudo python3 usb_recovery.py --list

# 디스크 이미지 생성 (복구 전 백업 권장)
sudo python3 usb_recovery.py --image /dev/sdb -o backup.img

# 시그니처 기반 파일 복구 (전체)
sudo python3 usb_recovery.py --recover /dev/sdb -o ./recovered/

# 특정 파일 형식만 복구
sudo python3 usb_recovery.py --recover /dev/sdb -t .jpg,.png,.pdf -o ./recovered/

# 마운트된 USB에서 파일 복사
python3 usb_recovery.py --copy /mnt/usb -o ./backup/

# 파일시스템 복구 시도
sudo python3 usb_recovery.py --repair /dev/sdb1
```

### 옵션

| 옵션 | 설명 |
|------|------|
| `--list`, `-l` | 저장 장치 목록 표시 |
| `--image`, `-i` | 디스크 이미지 생성 |
| `--recover`, `-r` | 파일 시그니처 기반 복구 |
| `--copy`, `-c` | 디렉토리 파일 복사 |
| `--repair` | 파일시스템 복구 시도 |
| `--output`, `-o` | 출력 경로 지정 |
| `--types`, `-t` | 복구할 파일 형식 (쉼표 구분) |
| `--max-files`, `-m` | 최대 복구 파일 수 |

## 복구 절차 (권장)

1. **장치 확인**: `--list`로 USB 장치 경로 확인
2. **이미지 백업**: `--image`로 디스크 이미지 생성 (원본 보호)
3. **파일 복구**: 이미지 파일에서 `--recover`로 파일 복구
4. **결과 확인**: 출력 폴더에서 복구된 파일 확인

## 주의사항

- 복구 작업은 반드시 **디스크 이미지**에서 수행하는 것을 권장합니다
- USB에 새로운 데이터를 기록하면 복구 가능성이 낮아집니다
- 손상된 USB는 가능한 빨리 복구를 시도하세요
- root 권한 없이도 마운트된 디렉토리 복구(`--copy`)는 사용 가능합니다
