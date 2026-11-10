import zipfile

from zip_analyzer.analyzer import analyze_zip
from zip_analyzer.rules import (
    find_high_ratio_files,
    find_overlapping_entries,
    is_disguised_executable,
)


def make_info(name, offset, csize, fsize):
    info = zipfile.ZipInfo(name)
    info.header_offset = offset
    info.compress_size = csize
    info.file_size = fsize
    return info


def make_zip(path, files):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return path


def test_high_ratio_detected():
    entries = [make_info("bomb.bin", 0, 10, 10_000)]
    assert find_high_ratio_files(entries) == ["bomb.bin"]


def test_normal_ratio_ok():
    entries = [make_info("a.txt", 0, 100, 300)]
    assert find_high_ratio_files(entries) == []


def test_overlap_detected():
    entries = [
        make_info("a.bin", 0, 1000, 5000),
        make_info("b.bin", 100, 1000, 5000),
    ]
    assert find_overlapping_entries(entries) == ["b.bin"]


def test_no_overlap_for_normal_layout():
    entries = [
        make_info("a.bin", 0, 100, 500),
        make_info("b.bin", 200, 100, 500),
    ]
    assert find_overlapping_entries(entries) == []


def test_disguised_exe():
    assert is_disguised_executable("foto.jpg", b"MZ\x90\x00")


def test_real_exe_not_flagged():
    assert not is_disguised_executable("setup.exe", b"MZ\x90\x00")


def test_clean_zip_has_hash_and_low_score(tmp_path):
    path = make_zip(tmp_path / "temiz.zip", {"a.txt": "merhaba " * 10})
    report = analyze_zip(path)
    assert report["risk_level"] == "LOW"
    assert report["risk_score"] == 0
    assert len(report["file_hashes"]) == 1
    assert len(report["file_hashes"][0]["sha256"]) == 64


def test_high_ratio_zip_skips_hash_and_scores_high(tmp_path):
    path = make_zip(tmp_path / "bomba.zip", {"z.bin": b"\x00" * 5_000_000})
    report = analyze_zip(path)
    assert report["high_ratio_files"] == ["z.bin"]
    assert report["file_hashes"] == []
    assert report["risk_score"] >= 70


def test_disguised_exe_in_zip(tmp_path):
    path = make_zip(tmp_path / "gizli.zip", {"foto.jpg": b"MZ\x90\x00abcd"})
    report = analyze_zip(path)
    assert report["disguised_files"] == ["foto.jpg"]
    assert report["risk_level"] == "HIGH"


def test_zip_slip_detected(tmp_path):
    path = make_zip(tmp_path / "slip.zip", {"../../evil.txt": "x"})
    report = analyze_zip(path)
    assert report["suspicious_paths"] == ["../../evil.txt"]
    assert report["risk_level"] == "HIGH"


def test_nested_bomb_detected(tmp_path):
    inner = make_zip(tmp_path / "ic.zip", {"z.bin": b"\x00" * 5_000_000})
    middle = tmp_path / "orta.zip"
    with zipfile.ZipFile(middle, "w") as z:
        z.write(inner, "ic.zip")
    outer = tmp_path / "dis.zip"
    with zipfile.ZipFile(outer, "w") as z:
        z.write(middle, "orta.zip")
    report = analyze_zip(outer)
    assert report["risk_level"] == "HIGH"
    assert report["risk_score"] >= 70


def test_missing_file_returns_error():
    report = analyze_zip("olmayan_dosya.zip")
    assert report["status"] == "ERROR"
    assert report["risk_score"] == 0