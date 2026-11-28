import py7zr

from zip_analyzer.sevenzip import analyze_7z


def make_7z(path, files):
    with py7zr.SevenZipFile(path, "w") as z:
        for name, data in files.items():
            z.writestr(data, name)
    return path


def test_clean_7z_is_low(tmp_path):
    path = make_7z(tmp_path / "temiz.7z", {"a.txt": "merhaba " * 10})
    report = analyze_7z(path)
    assert report["status"] == "OK"
    assert report["risk_level"] == "LOW"
    assert report["risk_score"] == 0


def test_double_extension_7z_is_high(tmp_path):
    path = make_7z(tmp_path / "cift.7z", {"fatura.pdf.exe": "x"})
    report = analyze_7z(path)
    assert report["double_extension_files"] == ["fatura.pdf.exe"]
    assert report["risk_level"] == "HIGH"


def test_high_ratio_7z_is_high(tmp_path):
    path = make_7z(tmp_path / "bomba.7z", {"z.bin": "\x00" * 5_000_000})
    report = analyze_7z(path)
    assert report["risk_level"] == "HIGH"
    assert report["risk_score"] >= 70


def test_missing_7z_returns_error():
    report = analyze_7z("olmayan.7z")
    assert report["status"] == "ERROR"