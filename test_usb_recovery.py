#!/usr/bin/env python3
"""
USB Recovery Tool - 기능 검증 테스트

테스트 항목:
  1. 파일 시그니처 데이터베이스 무결성
  2. 유틸리티 함수 (format_size, get_file_hash)
  3. 파일 시그니처 기반 스캔 및 복구 (File Carving)
  4. OLE/ZIP 기반 파일 형식 식별
  5. 디렉토리 기반 파일 복구
  6. 디스크 이미지 생성 (시뮬레이션)
  7. 파일시스템 감지
  8. 엣지 케이스 처리
"""

import os
import sys
import struct
import tempfile
import shutil
import hashlib
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# 테스트 대상 모듈 임포트
from usb_recovery import (
    FILE_SIGNATURES,
    MAX_SIG_LEN,
    DEFAULT_MAX_FILE_SIZE,
    DEFAULT_FALLBACK_SIZE,
    OLE_STREAM_SIGNATURES,
    ZIP_CONTENT_SIGNATURES,
    identify_ole_type,
    identify_zip_type,
    format_size,
    get_file_hash,
    USBRecoveryTool,
)


class TestFileSignatures(unittest.TestCase):
    """파일 시그니처 데이터베이스 검증"""

    def test_signatures_are_bytes(self):
        """모든 시그니처가 bytes 타입인지 확인"""
        for sig in FILE_SIGNATURES:
            self.assertIsInstance(sig, bytes, f"시그니처가 bytes가 아닙니다: {sig!r}")

    def test_signatures_have_required_fields(self):
        """모든 시그니처에 필수 필드가 있는지 확인"""
        for sig, info in FILE_SIGNATURES.items():
            self.assertIn('ext', info, f"ext 없음: {sig!r}")
            self.assertIn('name', info, f"name 없음: {sig!r}")
            self.assertTrue(info['ext'].startswith('.'),
                            f"확장자가 .으로 시작하지 않음: {info['ext']}")

    def test_max_sig_len_correct(self):
        """MAX_SIG_LEN이 올바른지 확인"""
        expected = max(len(sig) for sig in FILE_SIGNATURES)
        self.assertEqual(MAX_SIG_LEN, expected)

    def test_common_signatures_present(self):
        """주요 파일 형식의 시그니처가 포함되어 있는지 확인"""
        extensions = {info['ext'] for info in FILE_SIGNATURES.values()}
        expected_exts = {'.jpg', '.png', '.gif', '.pdf', '.doc', '.zip',
                         '.mp3', '.mp4', '.exe', '.html'}
        for ext in expected_exts:
            self.assertIn(ext, extensions, f"주요 형식 {ext} 시그니처가 누락되었습니다")

    def test_hwp_hwpx_signatures_present(self):
        """한글(HWP/HWPX) 파일 시그니처가 포함되어 있는지 확인"""
        extensions = {info['ext'] for info in FILE_SIGNATURES.values()}
        self.assertIn('.hwp', extensions, "HWP 시그니처가 누락되었습니다")
        # HWPX는 ZIP 기반이므로 ZIP_CONTENT_SIGNATURES에서 확인
        hwpx_found = any(ext == '.hwpx' for ext, _ in ZIP_CONTENT_SIGNATURES.values())
        self.assertTrue(hwpx_found, "HWPX 시그니처가 누락되었습니다")

    def test_footer_bytes_type(self):
        """footer가 bytes 또는 None인지 확인"""
        for sig, info in FILE_SIGNATURES.items():
            footer = info.get('footer')
            if footer is not None:
                self.assertIsInstance(footer, bytes,
                                     f"footer가 bytes가 아닙니다: {info['name']}")

    def test_default_max_file_sizes(self):
        """기본 파일 크기 제한값이 양수인지 확인"""
        for ext, size in DEFAULT_MAX_FILE_SIZE.items():
            self.assertGreater(size, 0, f"{ext}의 최대 크기가 0 이하입니다")
            self.assertTrue(ext.startswith('.'), f"확장자 형식 오류: {ext}")

    def test_default_fallback_size_positive(self):
        """기본 폴백 크기가 양수인지 확인"""
        self.assertGreater(DEFAULT_FALLBACK_SIZE, 0)


class TestFormatSize(unittest.TestCase):
    """format_size 함수 테스트"""

    def test_bytes(self):
        self.assertEqual(format_size(0), "0.00 B")
        self.assertEqual(format_size(512), "512.00 B")

    def test_kilobytes(self):
        self.assertEqual(format_size(1024), "1.00 KB")
        self.assertEqual(format_size(1536), "1.50 KB")

    def test_megabytes(self):
        self.assertEqual(format_size(1048576), "1.00 MB")

    def test_gigabytes(self):
        self.assertEqual(format_size(1073741824), "1.00 GB")

    def test_terabytes(self):
        self.assertEqual(format_size(1099511627776), "1.00 TB")

    def test_negative_size(self):
        self.assertEqual(format_size(-1), "Unknown")

    def test_large_size(self):
        """페타바이트 이상의 크기"""
        result = format_size(1125899906842624)  # 1 PB
        self.assertIn("PB", result)


class TestGetFileHash(unittest.TestCase):
    """get_file_hash 함수 테스트"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_md5_hash(self):
        """MD5 해시 계산 정확성"""
        filepath = os.path.join(self.temp_dir, 'test.bin')
        content = b'Hello, USB Recovery!'
        with open(filepath, 'wb') as f:
            f.write(content)

        expected = hashlib.md5(content).hexdigest()
        self.assertEqual(get_file_hash(filepath, 'md5'), expected)

    def test_sha256_hash(self):
        """SHA256 해시 계산 정확성"""
        filepath = os.path.join(self.temp_dir, 'test.bin')
        content = b'Test data for hashing'
        with open(filepath, 'wb') as f:
            f.write(content)

        expected = hashlib.sha256(content).hexdigest()
        self.assertEqual(get_file_hash(filepath, 'sha256'), expected)

    def test_empty_file_hash(self):
        """빈 파일 해시 계산"""
        filepath = os.path.join(self.temp_dir, 'empty.bin')
        with open(filepath, 'wb') as f:
            pass

        expected = hashlib.md5(b'').hexdigest()
        self.assertEqual(get_file_hash(filepath, 'md5'), expected)

    def test_large_file_hash(self):
        """큰 파일 해시 계산 (8192 바이트 이상)"""
        filepath = os.path.join(self.temp_dir, 'large.bin')
        content = b'\xaa' * 20000
        with open(filepath, 'wb') as f:
            f.write(content)

        expected = hashlib.md5(content).hexdigest()
        self.assertEqual(get_file_hash(filepath, 'md5'), expected)


class TestIdentifyOleType(unittest.TestCase):
    """OLE 복합 문서 형식 식별 테스트"""

    def test_hwp_detection(self):
        """HWP 문서 감지"""
        data = b'\x00' * 100 + b'HWP Document File' + b'\x00' * 100
        ext, name = identify_ole_type(data)
        self.assertEqual(ext, '.hwp')
        self.assertIn('HWP', name)

    def test_word_detection(self):
        """MS Word 문서 감지 (UTF-16 인코딩된 'WordDocument')"""
        data = b'\x00' * 100 + b'W\x00o\x00r\x00d\x00D\x00o\x00c\x00u\x00m\x00e\x00n\x00t' + b'\x00' * 100
        ext, name = identify_ole_type(data)
        self.assertEqual(ext, '.doc')

    def test_excel_detection(self):
        """MS Excel 문서 감지"""
        data = b'\x00' * 100 + b'W\x00o\x00r\x00k\x00b\x00o\x00o\x00k' + b'\x00' * 100
        ext, name = identify_ole_type(data)
        self.assertEqual(ext, '.xls')

    def test_powerpoint_detection(self):
        """MS PowerPoint 문서 감지"""
        data = b'\x00' * 100 + b'P\x00o\x00w\x00e\x00r\x00P\x00o\x00i\x00n\x00t' + b'\x00' * 100
        ext, name = identify_ole_type(data)
        self.assertEqual(ext, '.ppt')

    def test_unknown_ole_defaults_to_doc(self):
        """알 수 없는 OLE 문서의 기본값은 .doc"""
        data = b'\x00' * 8192
        ext, name = identify_ole_type(data)
        self.assertEqual(ext, '.doc')

    def test_hancom_hwp_detection(self):
        """한컴 HWP 감지 (Hancom 시그니처)"""
        data = b'\x00' * 100 + b'\x00Hancom' + b'\x00' * 100
        ext, name = identify_ole_type(data)
        self.assertEqual(ext, '.hwp')

    def test_ole_search_range_limit(self):
        """OLE 검색은 첫 8192 바이트로 제한"""
        # 시그니처가 8192 바이트 이후에 있으면 감지하지 못해야 함
        data = b'\x00' * 9000 + b'HWP Document File'
        ext, name = identify_ole_type(data)
        self.assertEqual(ext, '.doc')  # 감지 실패 -> 기본값


class TestIdentifyZipType(unittest.TestCase):
    """ZIP 기반 파일 형식 식별 테스트"""

    def test_docx_detection(self):
        """DOCX 문서 감지"""
        data = b'PK\x03\x04' + b'\x00' * 20 + b'word/' + b'\x00' * 100
        ext, name = identify_zip_type(data)
        self.assertEqual(ext, '.docx')
        self.assertIn('DOCX', name)

    def test_xlsx_detection(self):
        """XLSX 문서 감지"""
        data = b'PK\x03\x04' + b'\x00' * 20 + b'xl/' + b'\x00' * 100
        ext, name = identify_zip_type(data)
        self.assertEqual(ext, '.xlsx')

    def test_pptx_detection(self):
        """PPTX 문서 감지"""
        data = b'PK\x03\x04' + b'\x00' * 20 + b'ppt/' + b'\x00' * 100
        ext, name = identify_zip_type(data)
        self.assertEqual(ext, '.pptx')

    def test_hwpx_detection(self):
        """HWPX 문서 감지"""
        data = b'PK\x03\x04' + b'\x00' * 20 + b'Contents/' + b'\x00' * 100
        ext, name = identify_zip_type(data)
        self.assertEqual(ext, '.hwpx')
        self.assertIn('HWPX', name)

    def test_odt_detection(self):
        """ODT 문서 감지"""
        data = b'PK\x03\x04' + b'\x00' * 20 + b'mimetype' + b'opendocument.text' + b'\x00' * 100
        ext, name = identify_zip_type(data)
        self.assertEqual(ext, '.odt')

    def test_ods_detection(self):
        """ODS 스프레드시트 감지"""
        data = b'PK\x03\x04' + b'\x00' * 20 + b'mimetype' + b'opendocument.spreadsheet' + b'\x00' * 100
        ext, name = identify_zip_type(data)
        self.assertEqual(ext, '.ods')

    def test_odp_detection(self):
        """ODP 프레젠테이션 감지"""
        data = b'PK\x03\x04' + b'\x00' * 20 + b'mimetype' + b'opendocument.presentation' + b'\x00' * 100
        ext, name = identify_zip_type(data)
        self.assertEqual(ext, '.odp')

    def test_plain_zip_detection(self):
        """일반 ZIP 파일 감지"""
        data = b'PK\x03\x04' + b'\x00' * 100
        ext, name = identify_zip_type(data)
        self.assertEqual(ext, '.zip')

    def test_search_range_limit(self):
        """ZIP 검색은 첫 4096 바이트로 제한"""
        data = b'PK\x03\x04' + b'\x00' * 4096 + b'word/'
        ext, name = identify_zip_type(data)
        self.assertEqual(ext, '.zip')  # 범위 밖 -> 일반 ZIP


class TestUSBRecoveryToolInit(unittest.TestCase):
    """USBRecoveryTool 초기화 테스트"""

    def test_default_output_dir(self):
        """기본 출력 디렉토리 생성"""
        tool = USBRecoveryTool()
        self.assertTrue(tool.output_dir.startswith(os.path.expanduser('~')))
        self.assertIn('USB_Recovery_', tool.output_dir)

    def test_custom_output_dir(self):
        """사용자 지정 출력 디렉토리"""
        tool = USBRecoveryTool(output_dir='/tmp/test_recovery')
        self.assertEqual(tool.output_dir, '/tmp/test_recovery')

    def test_initial_state(self):
        """초기 상태 확인"""
        tool = USBRecoveryTool()
        self.assertEqual(tool.recovered_files, [])
        self.assertEqual(len(tool.scan_stats), 0)


class TestFileCarving(unittest.TestCase):
    """파일 시그니처 기반 복구 (File Carving) 테스트"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.output_dir = os.path.join(self.temp_dir, 'output')

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def _create_test_image(self, filename, content):
        """테스트용 디스크 이미지 생성"""
        filepath = os.path.join(self.temp_dir, filename)
        with open(filepath, 'wb') as f:
            f.write(content)
        return filepath

    def test_jpeg_recovery(self):
        """JPEG 파일 복구 테스트"""
        # JPEG 시그니처 + 더미 데이터 + JPEG 푸터
        jpeg_data = b'\xff\xd8\xff' + b'\x00' * 1000 + b'\xff\xd9'
        # 앞뒤에 패딩 추가
        image_data = b'\x00' * 512 + jpeg_data + b'\x00' * 512
        image_path = self._create_test_image('test.img', image_data)

        tool = USBRecoveryTool(output_dir=self.output_dir)
        tool.scan_by_signature(image_path, file_types=['.jpg'])

        self.assertEqual(len(tool.recovered_files), 1)
        self.assertEqual(tool.recovered_files[0]['type'], 'JPEG Image')
        # 복구된 파일의 크기가 원본과 일치하는지 확인 (시그니처~푸터)
        self.assertEqual(tool.recovered_files[0]['size'], len(jpeg_data))

    def test_png_recovery(self):
        """PNG 파일 복구 테스트"""
        png_header = b'\x89PNG\r\n\x1a\n'
        png_footer = b'\x00\x00\x00\x00IEND\xaeB`\x82'
        png_data = png_header + b'\x00' * 500 + png_footer
        image_data = b'\x00' * 1024 + png_data + b'\x00' * 1024
        image_path = self._create_test_image('test.img', image_data)

        tool = USBRecoveryTool(output_dir=self.output_dir)
        tool.scan_by_signature(image_path, file_types=['.png'])

        self.assertEqual(len(tool.recovered_files), 1)
        self.assertEqual(tool.recovered_files[0]['type'], 'PNG Image')

    def test_pdf_recovery(self):
        """PDF 파일 복구 테스트"""
        pdf_data = b'%PDF-1.4' + b'\x00' * 200 + b'%%EOF'
        image_data = pdf_data + b'\x00' * 512
        image_path = self._create_test_image('test.img', image_data)

        tool = USBRecoveryTool(output_dir=self.output_dir)
        tool.scan_by_signature(image_path, file_types=['.pdf'])

        self.assertEqual(len(tool.recovered_files), 1)
        self.assertEqual(tool.recovered_files[0]['type'], 'PDF Document')

    def test_multiple_file_recovery(self):
        """여러 파일 동시 복구 테스트"""
        jpeg_data = b'\xff\xd8\xff' + b'\xAA' * 200 + b'\xff\xd9'
        pdf_data = b'%PDF-1.4' + b'\xBB' * 200 + b'%%EOF'
        png_header = b'\x89PNG\r\n\x1a\n'
        png_footer = b'\x00\x00\x00\x00IEND\xaeB`\x82'
        png_data = png_header + b'\xCC' * 200 + png_footer

        image_data = (b'\x00' * 512 + jpeg_data +
                      b'\x00' * 512 + pdf_data +
                      b'\x00' * 512 + png_data +
                      b'\x00' * 512)
        image_path = self._create_test_image('test.img', image_data)

        tool = USBRecoveryTool(output_dir=self.output_dir)
        tool.scan_by_signature(image_path)

        # 최소 3개 파일이 복구되어야 함
        self.assertGreaterEqual(len(tool.recovered_files), 3)

    def test_max_files_limit(self):
        """최대 파일 수 제한 테스트"""
        # 3개의 JPEG 파일 생성
        jpeg1 = b'\xff\xd8\xff' + b'\x01' * 200 + b'\xff\xd9'
        jpeg2 = b'\xff\xd8\xff' + b'\x02' * 200 + b'\xff\xd9'
        jpeg3 = b'\xff\xd8\xff' + b'\x03' * 200 + b'\xff\xd9'
        image_data = (b'\x00' * 512 + jpeg1 +
                      b'\x00' * 512 + jpeg2 +
                      b'\x00' * 512 + jpeg3)
        image_path = self._create_test_image('test.img', image_data)

        tool = USBRecoveryTool(output_dir=self.output_dir)
        tool.scan_by_signature(image_path, file_types=['.jpg'], max_files=2)

        self.assertEqual(len(tool.recovered_files), 2)

    def test_small_file_skip(self):
        """너무 작은 파일 건너뛰기 테스트 (64 바이트 미만)"""
        # 시그니처 + 10 바이트 -> 매우 작은 파일
        jpeg_tiny = b'\xff\xd8\xff' + b'\x00' * 10 + b'\xff\xd9'
        image_data = jpeg_tiny + b'\x00' * 512
        image_path = self._create_test_image('test.img', image_data)

        tool = USBRecoveryTool(output_dir=self.output_dir)
        tool.scan_by_signature(image_path, file_types=['.jpg'])

        # 64 바이트 미만이므로 건너뛰어야 함
        self.assertEqual(len(tool.recovered_files), 0)

    def test_duplicate_file_skip(self):
        """중복 파일 건너뛰기 테스트"""
        # 동일한 데이터로 2개 파일 생성
        jpeg_data = b'\xff\xd8\xff' + b'\xAA' * 200 + b'\xff\xd9'
        image_data = (b'\x00' * 512 + jpeg_data +
                      b'\x00' * 512 + jpeg_data)
        image_path = self._create_test_image('test.img', image_data)

        tool = USBRecoveryTool(output_dir=self.output_dir)
        tool.scan_by_signature(image_path, file_types=['.jpg'])

        # 중복이므로 1개만 복구되어야 함
        self.assertEqual(len(tool.recovered_files), 1)

    def test_type_filter(self):
        """파일 형식 필터링 테스트"""
        jpeg_data = b'\xff\xd8\xff' + b'\xAA' * 200 + b'\xff\xd9'
        pdf_data = b'%PDF-1.4' + b'\xBB' * 200 + b'%%EOF'
        image_data = b'\x00' * 512 + jpeg_data + b'\x00' * 512 + pdf_data
        image_path = self._create_test_image('test.img', image_data)

        tool = USBRecoveryTool(output_dir=self.output_dir)
        tool.scan_by_signature(image_path, file_types=['.jpg'])

        # JPG만 필터했으므로 PDF는 복구되면 안 됨
        types = {f['type'] for f in tool.recovered_files}
        self.assertIn('JPEG Image', types)
        self.assertNotIn('PDF Document', types)

    def test_empty_source_file(self):
        """빈 소스 파일 처리"""
        image_path = self._create_test_image('empty.img', b'')

        tool = USBRecoveryTool(output_dir=self.output_dir)
        tool.scan_by_signature(image_path)

        self.assertEqual(len(tool.recovered_files), 0)

    def test_no_signatures_found(self):
        """시그니처 미발견 시 처리"""
        image_data = b'\x00' * 10000
        image_path = self._create_test_image('zeros.img', image_data)

        tool = USBRecoveryTool(output_dir=self.output_dir)
        tool.scan_by_signature(image_path)

        self.assertEqual(len(tool.recovered_files), 0)

    def test_invalid_type_filter(self):
        """존재하지 않는 파일 형식 필터"""
        image_data = b'\x00' * 1000
        image_path = self._create_test_image('test.img', image_data)

        tool = USBRecoveryTool(output_dir=self.output_dir)
        # .xyz 형식은 시그니처 DB에 없으므로 스캔이 즉시 종료됨
        tool.scan_by_signature(image_path, file_types=['.xyz'])
        self.assertEqual(len(tool.recovered_files), 0)

    def test_signature_at_boundary(self):
        """읽기 버퍼 경계에 걸친 시그니처 감지"""
        # 64KB 버퍼 경계에 걸치도록 시그니처 배치
        read_size = 64 * 1024
        offset = read_size - 2  # 시그니처가 경계에 걸침
        padding_before = b'\x00' * offset
        jpeg_data = b'\xff\xd8\xff' + b'\xDD' * 200 + b'\xff\xd9'
        image_data = padding_before + jpeg_data + b'\x00' * 512
        image_path = self._create_test_image('boundary.img', image_data)

        tool = USBRecoveryTool(output_dir=self.output_dir)
        tool.scan_by_signature(image_path, file_types=['.jpg'])

        self.assertEqual(len(tool.recovered_files), 1)

    def test_ole_type_detection_in_carving(self):
        """File Carving 시 OLE 파일 형식 세부 감지"""
        ole_header = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
        ole_data = ole_header + b'\x00' * 100 + b'HWP Document File' + b'\x00' * 500
        image_data = b'\x00' * 512 + ole_data + b'\x00' * 512
        image_path = self._create_test_image('ole.img', image_data)

        tool = USBRecoveryTool(output_dir=self.output_dir)
        tool.scan_by_signature(image_path)

        # OLE로 감지되고, HWP로 세분화되어야 함
        hwp_files = [f for f in tool.recovered_files
                     if f['path'].endswith('.hwp')]
        self.assertGreaterEqual(len(hwp_files), 1)

    def test_zip_type_detection_in_carving(self):
        """File Carving 시 ZIP 기반 파일 형식 세부 감지"""
        zip_header = b'PK\x03\x04'
        zip_data = zip_header + b'\x00' * 20 + b'word/' + b'\x00' * 500 + b'PK\x05\x06'
        image_data = b'\x00' * 512 + zip_data + b'\x00' * 512
        image_path = self._create_test_image('zip.img', image_data)

        tool = USBRecoveryTool(output_dir=self.output_dir)
        tool.scan_by_signature(image_path)

        # DOCX로 세분화되어야 함
        docx_files = [f for f in tool.recovered_files
                      if f['path'].endswith('.docx')]
        self.assertGreaterEqual(len(docx_files), 1)

    def test_recovered_files_have_correct_metadata(self):
        """복구된 파일의 메타데이터 정확성"""
        jpeg_data = b'\xff\xd8\xff' + b'\xEE' * 200 + b'\xff\xd9'
        image_data = b'\x00' * 512 + jpeg_data
        image_path = self._create_test_image('meta.img', image_data)

        tool = USBRecoveryTool(output_dir=self.output_dir)
        tool.scan_by_signature(image_path, file_types=['.jpg'])

        self.assertEqual(len(tool.recovered_files), 1)
        f_info = tool.recovered_files[0]

        self.assertIn('path', f_info)
        self.assertIn('type', f_info)
        self.assertIn('size', f_info)
        self.assertIn('offset', f_info)
        self.assertIn('hash', f_info)
        self.assertEqual(f_info['offset'], 512)
        self.assertEqual(f_info['size'], len(jpeg_data))
        self.assertTrue(os.path.exists(f_info['path']))


class TestDirectoryRecovery(unittest.TestCase):
    """디렉토리 기반 파일 복구 테스트"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.source_dir = os.path.join(self.temp_dir, 'source')
        self.output_dir = os.path.join(self.temp_dir, 'output')
        os.makedirs(self.source_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def _create_file(self, rel_path, content=b'test data'):
        """테스트 파일 생성"""
        filepath = os.path.join(self.source_dir, rel_path)
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'wb') as f:
            f.write(content)
        return filepath

    def test_basic_file_copy(self):
        """기본 파일 복사 테스트"""
        self._create_file('test.txt', b'Hello World')

        tool = USBRecoveryTool(output_dir=self.output_dir)
        tool.recover_from_directory(self.source_dir)

        self.assertEqual(len(tool.recovered_files), 1)
        dst_path = tool.recovered_files[0]['path']
        with open(dst_path, 'rb') as f:
            self.assertEqual(f.read(), b'Hello World')

    def test_subdirectory_recovery(self):
        """서브디렉토리 포함 복구"""
        self._create_file('dir1/file1.txt', b'File 1')
        self._create_file('dir1/dir2/file2.txt', b'File 2')
        self._create_file('file3.txt', b'File 3')

        tool = USBRecoveryTool(output_dir=self.output_dir)
        tool.recover_from_directory(self.source_dir)

        self.assertEqual(len(tool.recovered_files), 3)

    def test_hidden_files_included(self):
        """숨겨진 파일 포함 (기본값)"""
        self._create_file('.hidden_file', b'Hidden')
        self._create_file('.hidden_dir/file.txt', b'In hidden dir')
        self._create_file('normal.txt', b'Normal')

        tool = USBRecoveryTool(output_dir=self.output_dir)
        tool.recover_from_directory(self.source_dir, include_hidden=True)

        self.assertEqual(len(tool.recovered_files), 3)

    def test_hidden_files_excluded(self):
        """숨겨진 파일 제외"""
        self._create_file('.hidden_file', b'Hidden')
        self._create_file('.hidden_dir/file.txt', b'In hidden dir')
        self._create_file('normal.txt', b'Normal')

        tool = USBRecoveryTool(output_dir=self.output_dir)
        tool.recover_from_directory(self.source_dir, include_hidden=False)

        self.assertEqual(len(tool.recovered_files), 1)

    def test_nonexistent_source_directory(self):
        """존재하지 않는 소스 디렉토리"""
        tool = USBRecoveryTool(output_dir=self.output_dir)
        tool.recover_from_directory('/nonexistent/path')

        self.assertEqual(len(tool.recovered_files), 0)

    def test_empty_source_directory(self):
        """빈 소스 디렉토리"""
        tool = USBRecoveryTool(output_dir=self.output_dir)
        tool.recover_from_directory(self.source_dir)

        self.assertEqual(len(tool.recovered_files), 0)

    def test_file_metadata_preservation(self):
        """파일 메타데이터 보존 확인"""
        src = self._create_file('meta_test.txt', b'Metadata test')

        tool = USBRecoveryTool(output_dir=self.output_dir)
        tool.recover_from_directory(self.source_dir)

        self.assertEqual(len(tool.recovered_files), 1)
        f_info = tool.recovered_files[0]
        self.assertIn('path', f_info)
        self.assertIn('type', f_info)
        self.assertIn('size', f_info)
        self.assertIn('original', f_info)
        self.assertEqual(f_info['type'], 'Directory Copy')


class TestDiskImage(unittest.TestCase):
    """디스크 이미지 생성 테스트"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    @patch('usb_recovery.platform.system', return_value='Windows')
    def test_python_disk_image_creation(self, mock_system):
        """Python 기반 디스크 이미지 생성 (Windows 코드 경로)"""
        source_path = os.path.join(self.temp_dir, 'source.bin')
        image_path = os.path.join(self.temp_dir, 'output.img')

        source_data = b'\xAA' * 10000
        with open(source_path, 'wb') as f:
            f.write(source_data)

        tool = USBRecoveryTool(output_dir=self.temp_dir)
        result = tool.create_disk_image(source_path, image_path)

        self.assertIsNotNone(result)
        self.assertTrue(os.path.exists(image_path))
        with open(image_path, 'rb') as f:
            self.assertEqual(f.read(), source_data)


class TestFilesystemDetection(unittest.TestCase):
    """파일시스템 감지 테스트"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def _create_device_image(self, filename, data):
        filepath = os.path.join(self.temp_dir, filename)
        with open(filepath, 'wb') as f:
            f.write(data)
        return filepath

    @patch('usb_recovery.subprocess.run')
    def test_blkid_fallback(self, mock_run):
        """blkid 실패 시 수동 감지 테스트 - FAT"""
        mock_run.side_effect = FileNotFoundError()

        # FAT 시그니처가 있는 이미지 생성
        data = bytearray(b'\x00' * 0x100)
        data[0x36:0x36 + 3] = b'FAT'
        device_path = self._create_device_image('fat.img', bytes(data))

        tool = USBRecoveryTool()
        fs_type = tool._detect_filesystem(device_path)
        self.assertEqual(fs_type, 'vfat')

    @patch('usb_recovery.subprocess.run')
    def test_blkid_fallback_fat32(self, mock_run):
        """blkid 실패 시 수동 감지 테스트 - FAT32"""
        mock_run.side_effect = FileNotFoundError()

        data = bytearray(b'\x00' * 0x100)
        data[0x52:0x52 + 5] = b'FAT32'
        device_path = self._create_device_image('fat32.img', bytes(data))

        tool = USBRecoveryTool()
        fs_type = tool._detect_filesystem(device_path)
        self.assertEqual(fs_type, 'vfat')

    @patch('usb_recovery.subprocess.run')
    def test_blkid_fallback_ntfs(self, mock_run):
        """blkid 실패 시 수동 감지 테스트 - NTFS"""
        mock_run.side_effect = FileNotFoundError()

        data = bytearray(b'\x00' * 0x100)
        data[3:7] = b'NTFS'
        device_path = self._create_device_image('ntfs.img', bytes(data))

        tool = USBRecoveryTool()
        fs_type = tool._detect_filesystem(device_path)
        self.assertEqual(fs_type, 'ntfs')

    @patch('usb_recovery.subprocess.run')
    def test_blkid_fallback_ext(self, mock_run):
        """blkid 실패 시 수동 감지 테스트 - ext4"""
        mock_run.side_effect = FileNotFoundError()

        data = bytearray(b'\x00' * 0x440)
        struct.pack_into('<H', data, 0x438, 0xEF53)
        device_path = self._create_device_image('ext.img', bytes(data))

        tool = USBRecoveryTool()
        fs_type = tool._detect_filesystem(device_path)
        self.assertEqual(fs_type, 'ext4')

    @patch('usb_recovery.subprocess.run')
    def test_blkid_success(self, mock_run):
        """blkid 성공 시 결과 사용"""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = 'ntfs\n'
        mock_run.return_value = mock_result

        tool = USBRecoveryTool()
        fs_type = tool._detect_filesystem('/dev/sdb1')
        self.assertEqual(fs_type, 'ntfs')


class TestCommandLineArgs(unittest.TestCase):
    """명령행 인자 파싱 테스트"""

    @patch('sys.argv', ['usb_recovery.py', '--list'])
    @patch.object(USBRecoveryTool, 'list_usb_devices')
    @patch.object(USBRecoveryTool, 'check_permissions')
    def test_list_flag(self, mock_check, mock_list):
        """--list 플래그"""
        from usb_recovery import main
        main()
        mock_list.assert_called_once()

    @patch('sys.argv', ['usb_recovery.py', '--recover', '/dev/sdb', '-o', '/tmp/out', '-t', '.jpg,.png'])
    @patch.object(USBRecoveryTool, 'scan_by_signature')
    @patch.object(USBRecoveryTool, 'check_permissions')
    def test_recover_with_types(self, mock_check, mock_scan):
        """--recover 플래그 + 파일 형식 필터"""
        from usb_recovery import main
        main()
        mock_scan.assert_called_once_with('/dev/sdb', ['.jpg', '.png'], 0)

    @patch('sys.argv', ['usb_recovery.py', '--copy', '/mnt/usb', '-o', '/tmp/backup'])
    @patch.object(USBRecoveryTool, 'recover_from_directory')
    @patch.object(USBRecoveryTool, 'check_permissions')
    def test_copy_flag(self, mock_check, mock_copy):
        """--copy 플래그"""
        from usb_recovery import main
        main()
        mock_copy.assert_called_once_with('/mnt/usb')


class TestEdgeCases(unittest.TestCase):
    """엣지 케이스 테스트"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_permission_denied(self):
        """접근 권한 없는 파일 처리"""
        filepath = os.path.join(self.temp_dir, 'noaccess.img')
        with open(filepath, 'wb') as f:
            f.write(b'\x00' * 100)
        os.chmod(filepath, 0o000)

        tool = USBRecoveryTool(output_dir=os.path.join(self.temp_dir, 'out'))
        # PermissionError가 발생하더라도 크래시하지 않아야 함
        tool.scan_by_signature(filepath)
        self.assertEqual(len(tool.recovered_files), 0)

        # 정리를 위해 권한 복원
        os.chmod(filepath, 0o644)

    def test_scan_stats_tracking(self):
        """스캔 통계 추적"""
        jpeg_data = b'\xff\xd8\xff' + b'\xAA' * 200 + b'\xff\xd9'
        pdf_data = b'%PDF-1.4' + b'\xBB' * 200 + b'%%EOF'
        image_data = b'\x00' * 512 + jpeg_data + b'\x00' * 512 + pdf_data
        image_path = os.path.join(self.temp_dir, 'stats.img')
        with open(image_path, 'wb') as f:
            f.write(image_data)

        tool = USBRecoveryTool(output_dir=os.path.join(self.temp_dir, 'out'))
        tool.scan_by_signature(image_path)

        self.assertIn('.jpg', tool.scan_stats)
        self.assertIn('.pdf', tool.scan_stats)

    def test_output_directory_auto_creation(self):
        """출력 디렉토리 자동 생성"""
        output_dir = os.path.join(self.temp_dir, 'deep', 'nested', 'output')
        jpeg_data = b'\xff\xd8\xff' + b'\xFF' * 200 + b'\xff\xd9'
        image_path = os.path.join(self.temp_dir, 'test.img')
        with open(image_path, 'wb') as f:
            f.write(jpeg_data)

        tool = USBRecoveryTool(output_dir=output_dir)
        tool.scan_by_signature(image_path, file_types=['.jpg'])

        self.assertTrue(os.path.isdir(output_dir))

    def test_gif_recovery(self):
        """GIF 파일 복구"""
        gif_data = b'GIF89a' + b'\x00' * 200 + b'\x00\x3b'
        image_data = b'\x00' * 512 + gif_data + b'\x00' * 512
        image_path = os.path.join(self.temp_dir, 'gif.img')
        with open(image_path, 'wb') as f:
            f.write(image_data)

        tool = USBRecoveryTool(output_dir=os.path.join(self.temp_dir, 'out'))
        tool.scan_by_signature(image_path, file_types=['.gif'])

        self.assertEqual(len(tool.recovered_files), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
