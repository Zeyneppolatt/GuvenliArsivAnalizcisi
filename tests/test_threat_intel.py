import zipfile
from zip_analyzer.analyzer import analyze_zip


def test_yara_detects_eicar(tmp_path):
    zip_path = tmp_path / "eicar_test.zip"
    eicar_str = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("masum_not.txt", eicar_str)

    report = analyze_zip(zip_path, safe_mode=True)
    assert report["risk_level"] == "HIGH"
    assert report["threat_intel"]["yara_match_count"] == 1
    assert report["threat_intel"]["yara_scan"]["matches"][0]["rule"] == "EICAR_Test_Dosyasi"


def test_yara_detects_mz_header_in_txt(tmp_path):
    zip_path = tmp_path / "gizli_exe.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("fatura.txt", b"MZ\x90\x00\x03\x00\x00\x00")

    report = analyze_zip(zip_path, safe_mode=True)
    assert report["risk_level"] == "HIGH"
    rules_hit = [m["rule"] for m in report["threat_intel"]["yara_scan"]["matches"]]
    assert "Gizli_Calistirilabilir_Dosya_MZ" in rules_hit


def test_safe_mode_skips_bomb_in_yara(tmp_path):
    zip_path = tmp_path / "bomb.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("dev_dosya.txt", b"A" * (25 * 1024 * 1024))

    report = analyze_zip(zip_path, safe_mode=True)
    assert report["threat_intel"]["safe_mode"] is True
    assert "dev_dosya.txt" in report["threat_intel"]["yara_scan"]["skipped_safe_mode"]
