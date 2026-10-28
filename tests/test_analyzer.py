
import zipfile

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
    zip_path = tmp_path / "olmayan.zip"

    result = analyze_zip(zip_path)

    assert result["status"] == "ERROR"
    assert result["error"] == "Dosya bulunamadı."
