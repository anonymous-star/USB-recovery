#!/usr/bin/env python3
"""
USB Recovery Tool - 손상된 USB 드라이브에서 파일을 복구하는 도구

기능:
  1. USB 드라이브 감지 및 정보 표시
  2. 손상된 파일 시스템 스캔
  3. 삭제/손상된 파일 복구
  4. 파일 시그니처 기반 복구 (Raw Recovery)
  5. 디스크 이미지 생성 (안전한 복구를 위해)
"""

import os
import sys
import struct
import shutil
import hashlib
import argparse
import platform
import subprocess
import time
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# 파일 시그니처 데이터베이스 (매직 바이트)
FILE_SIGNATURES = {
    # 이미지 파일
    b'\xff\xd8\xff': {'ext': '.jpg', 'name': 'JPEG Image', 'footer': b'\xff\xd9'},
    b'\x89PNG\r\n\x1a\n': {'ext': '.png', 'name': 'PNG Image', 'footer': b'\x00\x00\x00\x00IEND\xaeB`\x82'},
    b'GIF87a': {'ext': '.gif', 'name': 'GIF Image (87a)', 'footer': b'\x00\x3b'},
    b'GIF89a': {'ext': '.gif', 'name': 'GIF Image (89a)', 'footer': b'\x00\x3b'},
    b'BM': {'ext': '.bmp', 'name': 'BMP Image', 'footer': None},
    b'\x00\x00\x01\x00': {'ext': '.ico', 'name': 'ICO Icon', 'footer': None},
    b'RIFF': {'ext': '.webp', 'name': 'WebP Image', 'footer': None},
    b'\x49\x49\x2a\x00': {'ext': '.tif', 'name': 'TIFF Image (LE)', 'footer': None},
    b'\x4d\x4d\x00\x2a': {'ext': '.tif', 'name': 'TIFF Image (BE)', 'footer': None},

    # 문서 파일
    b'%PDF': {'ext': '.pdf', 'name': 'PDF Document', 'footer': b'%%EOF'},
    b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': {'ext': '.doc', 'name': 'MS Office Document (OLE)', 'footer': None},
    b'PK\x03\x04': {'ext': '.zip', 'name': 'ZIP/DOCX/XLSX/PPTX Archive', 'footer': b'PK\x05\x06'},

    # 오디오/비디오 파일
    b'\x49\x44\x33': {'ext': '.mp3', 'name': 'MP3 Audio (ID3)', 'footer': None},
    b'\xff\xfb': {'ext': '.mp3', 'name': 'MP3 Audio', 'footer': None},
    b'\xff\xf3': {'ext': '.mp3', 'name': 'MP3 Audio', 'footer': None},
    b'\x00\x00\x00\x18ftypmp4': {'ext': '.mp4', 'name': 'MP4 Video', 'footer': None},
    b'\x00\x00\x00\x1cftypmp4': {'ext': '.mp4', 'name': 'MP4 Video', 'footer': None},
    b'\x00\x00\x00\x20ftypmp4': {'ext': '.mp4', 'name': 'MP4 Video', 'footer': None},
    b'\x00\x00\x00\x18ftypisom': {'ext': '.mp4', 'name': 'MP4 Video (isom)', 'footer': None},
    b'\x00\x00\x00\x1cftypisom': {'ext': '.mp4', 'name': 'MP4 Video (isom)', 'footer': None},
    b'fLaC': {'ext': '.flac', 'name': 'FLAC Audio', 'footer': None},
    b'OggS': {'ext': '.ogg', 'name': 'OGG Audio', 'footer': None},
    b'\x1aE\xdf\xa3': {'ext': '.mkv', 'name': 'MKV/WebM Video', 'footer': None},

    # 압축 파일
    b'\x1f\x8b': {'ext': '.gz', 'name': 'GZIP Archive', 'footer': None},
    b'Rar!\x1a\x07': {'ext': '.rar', 'name': 'RAR Archive', 'footer': None},
    b'7z\xbc\xaf\x27\x1c': {'ext': '.7z', 'name': '7-Zip Archive', 'footer': None},
    b'\xfd7zXZ\x00': {'ext': '.xz', 'name': 'XZ Archive', 'footer': None},
    b'BZh': {'ext': '.bz2', 'name': 'BZIP2 Archive', 'footer': None},

    # 실행 파일
    b'\x7fELF': {'ext': '.elf', 'name': 'ELF Executable', 'footer': None},
    b'MZ': {'ext': '.exe', 'name': 'Windows Executable', 'footer': None},

    # 텍스트/코드 파일
    b'<!DOCTYPE html': {'ext': '.html', 'name': 'HTML Document', 'footer': None},
    b'<html': {'ext': '.html', 'name': 'HTML Document', 'footer': None},
    b'<?xml': {'ext': '.xml', 'name': 'XML Document', 'footer': None},
    b'SQLite format 3': {'ext': '.sqlite', 'name': 'SQLite Database', 'footer': None},
}

# 최대 시그니처 길이 (스캔 버퍼 크기 결정용)
MAX_SIG_LEN = max(len(sig) for sig in FILE_SIGNATURES)

# 기본 최대 파일 크기 (시그니처 기반 복구 시)
DEFAULT_MAX_FILE_SIZE = {
    '.jpg': 50 * 1024 * 1024,     # 50MB
    '.png': 50 * 1024 * 1024,     # 50MB
    '.gif': 20 * 1024 * 1024,     # 20MB
    '.bmp': 100 * 1024 * 1024,    # 100MB
    '.pdf': 200 * 1024 * 1024,    # 200MB
    '.doc': 100 * 1024 * 1024,    # 100MB
    '.zip': 500 * 1024 * 1024,    # 500MB
    '.mp3': 50 * 1024 * 1024,     # 50MB
    '.mp4': 2 * 1024 * 1024 * 1024,  # 2GB
    '.mkv': 2 * 1024 * 1024 * 1024,  # 2GB
    '.exe': 100 * 1024 * 1024,    # 100MB
    '.rar': 500 * 1024 * 1024,    # 500MB
    '.7z': 500 * 1024 * 1024,     # 500MB
}
DEFAULT_FALLBACK_SIZE = 10 * 1024 * 1024  # 10MB


def format_size(size_bytes):
    """바이트 크기를 사람이 읽기 쉬운 형식으로 변환"""
    if size_bytes < 0:
        return "Unknown"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} PB"


def get_file_hash(filepath, algorithm='md5'):
    """파일 해시 계산"""
    h = hashlib.new(algorithm)
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


class USBRecoveryTool:
    """USB 복구 도구 메인 클래스"""

    def __init__(self, output_dir=None):
        self.output_dir = output_dir or os.path.join(
            os.path.expanduser('~'), 'USB_Recovery_' + datetime.now().strftime('%Y%m%d_%H%M%S')
        )
        self.recovered_files = []
        self.scan_stats = defaultdict(int)
        self.is_root = os.geteuid() == 0 if platform.system() != 'Windows' else True

    def check_permissions(self):
        """루트 권한 확인"""
        if platform.system() != 'Windows' and not self.is_root:
            print("\n[경고] 이 프로그램은 root 권한이 필요할 수 있습니다.")
            print("       USB 디바이스에 직접 접근하려면 sudo로 실행하세요.")
            print("       마운트된 디렉토리에서의 복구는 일반 권한으로도 가능합니다.\n")

    def list_usb_devices(self):
        """연결된 USB 장치 목록 표시"""
        print("\n" + "=" * 60)
        print("  연결된 저장 장치 목록")
        print("=" * 60)

        system = platform.system()

        if system == 'Linux':
            self._list_linux_devices()
        elif system == 'Darwin':
            self._list_macos_devices()
        elif system == 'Windows':
            self._list_windows_devices()
        else:
            print(f"[오류] 지원하지 않는 운영체제: {system}")

    def _list_linux_devices(self):
        """Linux에서 USB 장치 목록"""
        try:
            result = subprocess.run(
                ['lsblk', '-o', 'NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,MODEL', '-p'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                print(result.stdout)
            else:
                # lsblk가 없으면 /proc/partitions 사용
                print("\n장치 목록 (/proc/partitions):")
                with open('/proc/partitions', 'r') as f:
                    print(f.read())
        except FileNotFoundError:
            print("[오류] lsblk 명령을 찾을 수 없습니다.")
        except Exception as e:
            print(f"[오류] 장치 목록 조회 실패: {e}")

        # 마운트 포인트 표시
        try:
            result = subprocess.run(
                ['findmnt', '-t', 'vfat,ntfs,exfat,ext4,ext3,ext2', '-o', 'TARGET,SOURCE,FSTYPE,SIZE'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                print("\n마운트된 파일시스템:")
                print(result.stdout)
        except (FileNotFoundError, Exception):
            pass

    def _list_macos_devices(self):
        """macOS에서 USB 장치 목록"""
        try:
            result = subprocess.run(
                ['diskutil', 'list'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                print(result.stdout)
        except Exception as e:
            print(f"[오류] 장치 목록 조회 실패: {e}")

    def _list_windows_devices(self):
        """Windows에서 USB 장치 목록"""
        try:
            result = subprocess.run(
                ['wmic', 'diskdrive', 'get', 'Caption,Size,MediaType,InterfaceType'],
                capture_output=True, text=True, timeout=10, shell=True
            )
            if result.returncode == 0:
                print(result.stdout)

            # 드라이브 문자도 표시
            result2 = subprocess.run(
                ['wmic', 'logicaldisk', 'get', 'Caption,FileSystem,Size,FreeSpace,DriveType'],
                capture_output=True, text=True, timeout=10, shell=True
            )
            if result2.returncode == 0:
                print("\n논리 드라이브:")
                print(result2.stdout)
        except Exception as e:
            print(f"[오류] 장치 목록 조회 실패: {e}")

    def create_disk_image(self, source, image_path=None):
        """디스크 이미지 생성 (안전한 복구를 위해)"""
        if not image_path:
            image_path = os.path.join(self.output_dir, 'disk_image.img')

        os.makedirs(os.path.dirname(image_path), exist_ok=True)

        print(f"\n[*] 디스크 이미지 생성 중...")
        print(f"    소스: {source}")
        print(f"    대상: {image_path}")

        system = platform.system()

        if system in ('Linux', 'Darwin'):
            try:
                # dd 명령으로 이미지 생성
                result = subprocess.run(
                    ['dd', f'if={source}', f'of={image_path}',
                     'bs=4M', 'conv=noerror,sync', 'status=progress'],
                    capture_output=False, timeout=None
                )
                if result.returncode == 0:
                    size = os.path.getsize(image_path)
                    print(f"\n[+] 디스크 이미지 생성 완료: {format_size(size)}")
                    return image_path
                else:
                    print("[오류] 디스크 이미지 생성 실패")
                    return None
            except Exception as e:
                print(f"[오류] 디스크 이미지 생성 실패: {e}")
                return None
        else:
            # Python으로 직접 복사
            try:
                block_size = 4 * 1024 * 1024  # 4MB
                total_copied = 0
                errors = 0

                with open(source, 'rb') as src, open(image_path, 'wb') as dst:
                    while True:
                        try:
                            block = src.read(block_size)
                            if not block:
                                break
                            dst.write(block)
                            total_copied += len(block)
                            print(f"\r    복사됨: {format_size(total_copied)}, 오류: {errors}", end='', flush=True)
                        except IOError:
                            # 읽기 오류 시 빈 블록으로 채움
                            dst.write(b'\x00' * block_size)
                            total_copied += block_size
                            errors += 1

                print(f"\n[+] 디스크 이미지 생성 완료: {format_size(total_copied)} (오류 블록: {errors})")
                return image_path
            except Exception as e:
                print(f"[오류] 디스크 이미지 생성 실패: {e}")
                return None

    def scan_by_signature(self, source, file_types=None, max_files=0):
        """파일 시그니처 기반 스캔 및 복구 (Raw Recovery / File Carving)"""
        os.makedirs(self.output_dir, exist_ok=True)

        print(f"\n{'=' * 60}")
        print(f"  파일 시그니처 기반 스캔 (File Carving)")
        print(f"{'=' * 60}")
        print(f"  소스: {source}")
        print(f"  출력: {self.output_dir}")
        if file_types:
            print(f"  대상: {', '.join(file_types)}")
        print()

        # 검색할 시그니처 필터링
        signatures = {}
        for sig, info in FILE_SIGNATURES.items():
            if file_types is None or info['ext'] in file_types:
                signatures[sig] = info

        if not signatures:
            print("[오류] 검색할 파일 시그니처가 없습니다.")
            return

        print(f"[*] {len(signatures)}개 파일 형식 검색 중...")

        block_size = 512  # 섹터 크기
        read_size = 64 * 1024  # 64KB 읽기 버퍼
        total_scanned = 0
        file_count = 0
        found_positions = []  # (offset, signature, info)

        try:
            source_size = os.path.getsize(source)
        except OSError:
            source_size = 0

        start_time = time.time()

        # 1단계: 시그니처 위치 스캔
        print("[*] 1단계: 파일 시그니처 검색 중...")
        try:
            with open(source, 'rb') as f:
                overlap = MAX_SIG_LEN - 1
                prev_tail = b''

                while True:
                    data = f.read(read_size)
                    if not data:
                        break

                    # 이전 블록 끝과 현재 블록 시작 부분을 연결하여 경계에 걸친 시그니처 감지
                    search_data = prev_tail + data
                    search_offset = total_scanned - len(prev_tail)

                    for sig, info in signatures.items():
                        pos = 0
                        while True:
                            pos = search_data.find(sig, pos)
                            if pos == -1:
                                break
                            actual_offset = search_offset + pos
                            if actual_offset >= 0:  # 유효한 오프셋만
                                found_positions.append((actual_offset, sig, info))
                                self.scan_stats[info['ext']] += 1
                            pos += 1

                    total_scanned += len(data)
                    prev_tail = data[-overlap:] if len(data) >= overlap else data

                    # 진행률 표시
                    if source_size > 0:
                        progress = (total_scanned / source_size) * 100
                        elapsed = time.time() - start_time
                        speed = total_scanned / elapsed if elapsed > 0 else 0
                        print(f"\r    스캔: {format_size(total_scanned)} / {format_size(source_size)} "
                              f"({progress:.1f}%) | 속도: {format_size(speed)}/s | "
                              f"발견: {len(found_positions)}개", end='', flush=True)
                    else:
                        print(f"\r    스캔: {format_size(total_scanned)} | "
                              f"발견: {len(found_positions)}개", end='', flush=True)

        except PermissionError:
            print(f"\n[오류] 접근 권한이 없습니다: {source}")
            print("       sudo로 실행하거나 올바른 경로를 지정하세요.")
            return
        except Exception as e:
            print(f"\n[오류] 스캔 중 오류 발생: {e}")

        print(f"\n\n[+] 스캔 완료: {len(found_positions)}개 파일 시그니처 발견\n")

        # 오프셋 순으로 정렬
        found_positions.sort(key=lambda x: x[0])

        # 2단계: 파일 추출
        if found_positions:
            print("[*] 2단계: 파일 추출 중...")
            file_count = self._extract_files(source, found_positions, max_files)

        # 결과 요약
        self._print_summary(file_count, total_scanned, start_time)

    def _extract_files(self, source, found_positions, max_files):
        """발견된 시그니처로부터 파일 추출"""
        file_count = 0
        seen_hashes = set()

        try:
            with open(source, 'rb') as f:
                for i, (offset, sig, info) in enumerate(found_positions):
                    if max_files > 0 and file_count >= max_files:
                        print(f"\n[*] 최대 파일 수({max_files})에 도달했습니다.")
                        break

                    ext = info['ext']
                    max_size = DEFAULT_MAX_FILE_SIZE.get(ext, DEFAULT_FALLBACK_SIZE)

                    # 파일 형식별 디렉토리 생성
                    type_dir = os.path.join(self.output_dir, ext.lstrip('.').upper())
                    os.makedirs(type_dir, exist_ok=True)

                    # 파일 데이터 읽기
                    f.seek(offset)
                    file_data = f.read(max_size)

                    if not file_data:
                        continue

                    # 파일 끝 찾기 (footer가 있는 경우)
                    footer = info.get('footer')
                    if footer:
                        footer_pos = file_data.find(footer, len(sig))
                        if footer_pos != -1:
                            file_data = file_data[:footer_pos + len(footer)]

                    # 너무 작은 파일은 건너뛰기 (보통 오탐)
                    if len(file_data) < 64:
                        continue

                    # 중복 파일 확인 (해시 기반)
                    file_hash = hashlib.md5(file_data).hexdigest()
                    if file_hash in seen_hashes:
                        continue
                    seen_hashes.add(file_hash)

                    # 파일 저장
                    filename = f"recovered_{file_count:06d}_{offset:#010x}{ext}"
                    filepath = os.path.join(type_dir, filename)

                    with open(filepath, 'wb') as out:
                        out.write(file_data)

                    file_count += 1
                    self.recovered_files.append({
                        'path': filepath,
                        'type': info['name'],
                        'size': len(file_data),
                        'offset': offset,
                        'hash': file_hash
                    })

                    print(f"    [{file_count}] {info['name']}: {filename} "
                          f"({format_size(len(file_data))})")

        except Exception as e:
            print(f"\n[오류] 파일 추출 중 오류: {e}")

        return file_count

    def recover_from_directory(self, source_dir, include_hidden=True):
        """마운트된 디렉토리에서 접근 가능한 파일 복사 (손상된 USB가 마운트된 경우)"""
        os.makedirs(self.output_dir, exist_ok=True)

        print(f"\n{'=' * 60}")
        print(f"  디렉토리 기반 파일 복구")
        print(f"{'=' * 60}")
        print(f"  소스: {source_dir}")
        print(f"  출력: {self.output_dir}")
        print()

        if not os.path.isdir(source_dir):
            print(f"[오류] 디렉토리가 존재하지 않습니다: {source_dir}")
            return

        file_count = 0
        error_count = 0
        total_size = 0
        start_time = time.time()

        for root, dirs, files in os.walk(source_dir, onerror=lambda e: None):
            # 숨겨진 디렉토리 필터링
            if not include_hidden:
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                files = [f for f in files if not f.startswith('.')]

            for filename in files:
                src_path = os.path.join(root, filename)
                rel_path = os.path.relpath(src_path, source_dir)
                dst_path = os.path.join(self.output_dir, 'directory_recovery', rel_path)

                try:
                    os.makedirs(os.path.dirname(dst_path), exist_ok=True)

                    # 파일 복사 (메타데이터 보존)
                    shutil.copy2(src_path, dst_path)
                    file_size = os.path.getsize(dst_path)

                    file_count += 1
                    total_size += file_size
                    self.recovered_files.append({
                        'path': dst_path,
                        'type': 'Directory Copy',
                        'size': file_size,
                        'original': src_path,
                    })

                    print(f"    [+] {rel_path} ({format_size(file_size)})")

                except (IOError, OSError) as e:
                    error_count += 1
                    print(f"    [!] 실패: {rel_path} - {e}")

        elapsed = time.time() - start_time
        print(f"\n{'=' * 60}")
        print(f"  복구 완료")
        print(f"  복구된 파일: {file_count}개 ({format_size(total_size)})")
        print(f"  실패한 파일: {error_count}개")
        print(f"  소요 시간: {elapsed:.1f}초")
        print(f"  출력 위치: {self.output_dir}")
        print(f"{'=' * 60}\n")

    def repair_filesystem(self, device):
        """파일시스템 복구 시도 (시스템 도구 활용)"""
        print(f"\n{'=' * 60}")
        print(f"  파일시스템 복구")
        print(f"{'=' * 60}")
        print(f"  장치: {device}")
        print()

        if platform.system() == 'Windows':
            print("[*] Windows chkdsk 실행 중...")
            try:
                result = subprocess.run(
                    ['chkdsk', device, '/f'],
                    capture_output=True, text=True, timeout=600, shell=True
                )
                print(result.stdout)
                if result.returncode != 0:
                    print(f"[경고] chkdsk 경고/오류:\n{result.stderr}")
            except Exception as e:
                print(f"[오류] chkdsk 실행 실패: {e}")

        elif platform.system() == 'Linux':
            # 파일시스템 타입 감지
            fs_type = self._detect_filesystem(device)
            print(f"[*] 감지된 파일시스템: {fs_type or '알 수 없음'}")

            if fs_type in ('vfat', 'fat32', 'fat16', 'fat12'):
                print("[*] dosfsck 실행 중...")
                try:
                    result = subprocess.run(
                        ['dosfsck', '-a', '-v', device],
                        capture_output=True, text=True, timeout=600
                    )
                    print(result.stdout)
                except FileNotFoundError:
                    print("[오류] dosfsck가 설치되어 있지 않습니다.")
                    print("       설치: sudo apt install dosfstools")
                except Exception as e:
                    print(f"[오류] dosfsck 실행 실패: {e}")

            elif fs_type in ('ntfs',):
                print("[*] ntfsfix 실행 중...")
                try:
                    result = subprocess.run(
                        ['ntfsfix', device],
                        capture_output=True, text=True, timeout=600
                    )
                    print(result.stdout)
                except FileNotFoundError:
                    print("[오류] ntfsfix가 설치되어 있지 않습니다.")
                    print("       설치: sudo apt install ntfs-3g")
                except Exception as e:
                    print(f"[오류] ntfsfix 실행 실패: {e}")

            elif fs_type in ('ext2', 'ext3', 'ext4'):
                print("[*] e2fsck 실행 중...")
                try:
                    result = subprocess.run(
                        ['e2fsck', '-y', '-v', device],
                        capture_output=True, text=True, timeout=600
                    )
                    print(result.stdout)
                except FileNotFoundError:
                    print("[오류] e2fsck가 설치되어 있지 않습니다.")
                except Exception as e:
                    print(f"[오류] e2fsck 실행 실패: {e}")
            else:
                print(f"[오류] 지원하지 않는 파일시스템: {fs_type}")
                print("       fsck를 수동으로 실행하세요.")

        elif platform.system() == 'Darwin':
            print("[*] diskutil repairDisk 실행 중...")
            try:
                result = subprocess.run(
                    ['diskutil', 'repairDisk', device],
                    capture_output=True, text=True, timeout=600
                )
                print(result.stdout)
            except Exception as e:
                print(f"[오류] 복구 실행 실패: {e}")

    def _detect_filesystem(self, device):
        """파일시스템 타입 감지"""
        try:
            result = subprocess.run(
                ['blkid', '-o', 'value', '-s', 'TYPE', device],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip().lower()
        except Exception:
            pass

        # blkid가 실패하면 수동으로 확인
        try:
            with open(device, 'rb') as f:
                # FAT 확인
                f.seek(0x36)
                fat_label = f.read(8)
                if fat_label.startswith(b'FAT'):
                    return 'vfat'

                f.seek(0x52)
                fat32_label = f.read(8)
                if fat32_label.startswith(b'FAT32'):
                    return 'vfat'

                # NTFS 확인
                f.seek(3)
                ntfs_label = f.read(4)
                if ntfs_label == b'NTFS':
                    return 'ntfs'

                # ext 확인
                f.seek(0x438)
                magic = struct.unpack('<H', f.read(2))[0]
                if magic == 0xEF53:
                    return 'ext4'
        except Exception:
            pass

        return None

    def _print_summary(self, file_count, total_scanned, start_time):
        """스캔 결과 요약 출력"""
        elapsed = time.time() - start_time

        print(f"\n{'=' * 60}")
        print(f"  스캔 결과 요약")
        print(f"{'=' * 60}")
        print(f"  스캔한 데이터: {format_size(total_scanned)}")
        print(f"  소요 시간:     {elapsed:.1f}초")
        print(f"  복구된 파일:   {file_count}개")

        if self.scan_stats:
            print(f"\n  파일 형식별 발견 수:")
            for ext, count in sorted(self.scan_stats.items(), key=lambda x: x[1], reverse=True):
                print(f"    {ext:8s}: {count}개")

        print(f"\n  출력 위치: {self.output_dir}")
        print(f"{'=' * 60}\n")


def interactive_mode(tool):
    """대화형 모드"""
    print("""
╔══════════════════════════════════════════════════════════╗
║           USB Recovery Tool v1.0                        ║
║           USB 복구 도구                                  ║
╚══════════════════════════════════════════════════════════╝
    """)

    tool.check_permissions()

    while True:
        print("\n메뉴를 선택하세요:")
        print("  1. 연결된 저장 장치 목록 보기")
        print("  2. 디스크 이미지 생성 (권장: 복구 전 백업)")
        print("  3. 파일 시그니처 기반 복구 (File Carving)")
        print("  4. 디렉토리 기반 파일 복구 (마운트된 USB)")
        print("  5. 파일시스템 복구 시도")
        print("  6. 복구 결과 보기")
        print("  0. 종료")

        try:
            choice = input("\n선택 [0-6]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n\n프로그램을 종료합니다.")
            break

        if choice == '0':
            print("\n프로그램을 종료합니다. 복구된 파일이 있다면 출력 폴더를 확인하세요.")
            break

        elif choice == '1':
            tool.list_usb_devices()

        elif choice == '2':
            source = input("소스 장치 경로 (예: /dev/sdb): ").strip()
            if source:
                image_path = input("이미지 저장 경로 (Enter=기본값): ").strip() or None
                tool.create_disk_image(source, image_path)
            else:
                print("[오류] 소스 경로를 입력하세요.")

        elif choice == '3':
            source = input("소스 경로 (장치 또는 이미지 파일): ").strip()
            if not source:
                print("[오류] 소스 경로를 입력하세요.")
                continue

            print("\n복구할 파일 형식 (쉼표로 구분, Enter=전체):")
            print("  예: .jpg,.png,.pdf,.mp4,.doc,.zip,.mp3")
            types_input = input("파일 형식: ").strip()
            file_types = [t.strip() for t in types_input.split(',') if t.strip()] or None

            max_input = input("최대 복구 파일 수 (Enter=무제한): ").strip()
            max_files = int(max_input) if max_input.isdigit() else 0

            tool.scan_by_signature(source, file_types, max_files)

        elif choice == '4':
            source_dir = input("USB 마운트 경로 (예: /mnt/usb): ").strip()
            if source_dir:
                tool.recover_from_directory(source_dir)
            else:
                print("[오류] 경로를 입력하세요.")

        elif choice == '5':
            device = input("장치 경로 (예: /dev/sdb1): ").strip()
            if device:
                confirm = input(f"[경고] {device}의 파일시스템을 복구하시겠습니까? (y/N): ").strip().lower()
                if confirm == 'y':
                    tool.repair_filesystem(device)
                else:
                    print("취소되었습니다.")
            else:
                print("[오류] 장치 경로를 입력하세요.")

        elif choice == '6':
            if tool.recovered_files:
                print(f"\n복구된 파일: {len(tool.recovered_files)}개")
                for i, f_info in enumerate(tool.recovered_files, 1):
                    print(f"  {i}. [{f_info['type']}] {os.path.basename(f_info['path'])} "
                          f"({format_size(f_info['size'])})")
                print(f"\n출력 폴더: {tool.output_dir}")
            else:
                print("\n아직 복구된 파일이 없습니다.")

        else:
            print("[오류] 올바른 메뉴 번호를 입력하세요.")


def main():
    parser = argparse.ArgumentParser(
        description='USB Recovery Tool - 손상된 USB 드라이브에서 파일을 복구합니다',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  # 대화형 모드
  sudo python3 usb_recovery.py

  # 장치 목록 보기
  sudo python3 usb_recovery.py --list

  # USB 디스크 이미지 생성
  sudo python3 usb_recovery.py --image /dev/sdb -o backup.img

  # 시그니처 기반 파일 복구 (전체)
  sudo python3 usb_recovery.py --recover /dev/sdb -o ./recovered/

  # JPG, PNG 파일만 복구
  sudo python3 usb_recovery.py --recover /dev/sdb -t .jpg,.png -o ./recovered/

  # 마운트된 USB에서 파일 복사
  python3 usb_recovery.py --copy /mnt/usb -o ./backup/

  # 파일시스템 복구
  sudo python3 usb_recovery.py --repair /dev/sdb1
        """)

    parser.add_argument('--list', '-l', action='store_true',
                        help='연결된 저장 장치 목록 표시')
    parser.add_argument('--image', '-i', metavar='DEVICE',
                        help='디스크 이미지 생성 (소스 장치 경로)')
    parser.add_argument('--recover', '-r', metavar='SOURCE',
                        help='파일 시그니처 기반 복구 (장치/이미지 경로)')
    parser.add_argument('--copy', '-c', metavar='DIR',
                        help='마운트된 디렉토리에서 파일 복사')
    parser.add_argument('--repair', metavar='DEVICE',
                        help='파일시스템 복구 시도')
    parser.add_argument('--output', '-o', metavar='PATH',
                        help='출력 경로 (기본: ~/USB_Recovery_날짜)')
    parser.add_argument('--types', '-t', metavar='TYPES',
                        help='복구할 파일 형식 (쉼표 구분, 예: .jpg,.png,.pdf)')
    parser.add_argument('--max-files', '-m', type=int, default=0,
                        help='최대 복구 파일 수 (기본: 무제한)')

    args = parser.parse_args()

    # 출력 디렉토리 설정
    output_dir = args.output if args.output else None
    tool = USBRecoveryTool(output_dir=output_dir)

    # 파일 형식 파싱
    file_types = None
    if args.types:
        file_types = [t.strip() for t in args.types.split(',') if t.strip()]

    # 명령행 인자가 없으면 대화형 모드
    if not any([args.list, args.image, args.recover, args.copy, args.repair]):
        interactive_mode(tool)
        return

    # 명령행 모드
    tool.check_permissions()

    if args.list:
        tool.list_usb_devices()

    if args.image:
        image_path = args.output if args.output else None
        tool.create_disk_image(args.image, image_path)

    if args.recover:
        tool.scan_by_signature(args.recover, file_types, args.max_files)

    if args.copy:
        tool.recover_from_directory(args.copy)

    if args.repair:
        tool.repair_filesystem(args.repair)


if __name__ == '__main__':
    main()
