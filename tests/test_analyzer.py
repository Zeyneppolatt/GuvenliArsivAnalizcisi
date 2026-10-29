
import json
import zipfile

from main import main
from zip_analyzer.analyzer import analyze_zip


def test_valid_zip(tmp_path):
    zip_path = tmp_path / "test.zip"

    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("ornek.txt", "Merhaba, bu bir test dosyası.")

    result = analyze_zip(zip_path)

    assert result["status"] == "OK"
    assert result["risk_level"] == "LOW"
    assert result["total_files"] == 1
    assert result["error"] is None


def test_invalid_zip(tmp_path):
    zip_path = tmp_path / "bozuk.zip"
    zip_path.write_text("Bu bir ZIP dosyası değil.")

    result = analyze_zip(zip_path)

    assert result["status"] == "ERROR"
    assert "Arşiv okunamadı" in result["error"]


def test_missing_file(tmp_path):
    result = analyze_zip(tmp_path / "olmayan.zip")

    assert result["status"] == "ERROR"
    assert result["error"] == "Dosya bulunamadı."


def test_empty_zip(tmp_path):
    zip_path = tmp_path / "bos.zip"

    with zipfile.ZipFile(zip_path, "w"):
        pass

    result = analyze_zip(zip_path)

    assert result["status"] == "OK"
    assert result["total_files"] == 0
    assert result["error"] is None


def test_suspicious_path_warning(tmp_path):
    zip_path = tmp_path / "supheli.zip"

    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("../gizli.txt", "test")

    result = analyze_zip(zip_path)

    assert result["status"] == "OK"
    assert any(
        "Şüpheli dosya yolu bulundu" in warning
        for warning in result["warnings"]
    )


def test_suspicious_path_sets_high_risk(tmp_path):
    zip_path = tmp_path / "riskli.zip"

    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("../gizli.txt", "test")

    result = analyze_zip(zip_path)

    assert result["status"] == "OK"
    assert result["risk_level"] == "HIGH"


def test_zip_with_invalid_content(tmp_path):
    zip_path = tmp_path / "bozuk_icerik.zip"
    zip_path.write_bytes(b"Bu kesinlikle gecerli bir ZIP dosyasi degil.")

    result = analyze_zip(zip_path)

    assert result["status"] == "ERROR"
    assert result["error"] is not None
    assert "Arşiv okunamadı" in result["error"]


def test_cli_prints_json(tmp_path, monkeypatch, capsys):
    zip_path = tmp_path / "test.zip"

    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("ornek.txt", "test")

    monkeypatch.setattr(
        "sys.argv",
        ["main.py", str(zip_path), "--pretty"],
    )

    exit_code = main()
    output = capsys.readouterr().out
    report = json.loads(output)

    assert exit_code == 0
    assert report["status"] == "OK"


def test_cli_saves_json_report(tmp_path, monkeypatch, capsys):
    zip_path = tmp_path / "test.zip"
    output_path = tmp_path / "rapor.json"

    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("ornek.txt", "test")

    monkeypatch.setattr(
        "sys.argv",
        ["main.py", str(zip_path), "--output", str(output_path)],
    )

    exit_code = main()
    saved_report = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert saved_report["status"] == "OK"
    assert "Rapor kaydedildi" in capsys.readouterr().out


def test_cli_returns_error_for_missing_archive(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        ["main.py", str(tmp_path / "olmayan.zip")],
    )

    exit_code = main()

    assert exit_code == 1


def test_cli_handles_output_error(tmp_path, monkeypatch, capsys):
    zip_path = tmp_path / "test.zip"

    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("ornek.txt", "test")

    # Var olan bir dosyayı klasör gibi kullanarak yazma hatası oluştur.
    not_a_directory = tmp_path / "dosya.txt"
    not_a_directory.write_text("test")

    output_path = not_a_directory / "rapor.json"

    monkeypatch.setattr(
        "sys.argv",
        ["main.py", str(zip_path), "--output", str(output_path)],
    )

    exit_code = main()

    assert exit_code == 2
    assert "Rapor dosyası kaydedilemedi" in capsys.readouterr().err

def test_file_types_are_reported(tmp_path):
    zip_path = tmp_path / "turler.zip"

    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("belge.txt", "metin")
        archive.writestr("resim.png", "resim")
        archive.writestr("ikinci.txt", "başka metin")
        archive.writestr("README", "uzantısız dosya")

    result = analyze_zip(zip_path)

    assert result["status"] == "OK"
    assert result["file_types"] == {
        "[uzantısız]": 1,
        ".png": 1,
        ".txt": 2,
    }


def test_cli_summary(capsys, monkeypatch, tmp_path):
    from main import main

    zip_path = tmp_path / "ozet.zip"

    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("belge.txt", "test")

    monkeypatch.setattr(
        "sys.argv",
        ["main.py", str(zip_path), "--summary"],
    )

    exit_code = main()
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Risk seviyesi: LOW" in output
    assert "Dosya sayısı: 1" in output
    assert ".txt: 1" in output

def test_analyze_folder_with_multiple_zips(tmp_path):
    from main import analyze_path

    for name in ("bir.zip", "iki.zip"):
        with zipfile.ZipFile(tmp_path / name, "w") as archive:
            archive.writestr("belge.txt", "test")

    reports = analyze_path(tmp_path)

    assert len(reports) == 2
    assert all(report["status"] == "OK" for report in reports)


def test_analyze_empty_folder(tmp_path):
    from main import analyze_path

    reports = analyze_path(tmp_path)

    assert reports == []


def test_analyze_folder_ignores_non_zip_files(tmp_path):
    from main import analyze_path

    (tmp_path / "notlar.txt").write_text("ZIP değil.")

    with zipfile.ZipFile(tmp_path / "test.zip", "w") as archive:
        archive.writestr("belge.txt", "test")

    reports = analyze_path(tmp_path)

    assert len(reports) == 1
    assert reports[0]["file_name"] == "test.zip"


def test_analyze_path_missing_target(tmp_path):
    from main import analyze_path

    reports = analyze_path(tmp_path / "olmayan")

    assert len(reports) == 1
    assert reports[0]["status"] == "ERROR"
    assert reports[0]["error"] == "Dosya veya klasör bulunamadı."
