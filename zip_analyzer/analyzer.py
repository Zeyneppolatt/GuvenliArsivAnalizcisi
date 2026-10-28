
import zipfile
from pathlib import Path

from zip_analyzer.rules import evaluate_archive


ARCHIVE_EXTENSIONS = (".zip", ".rar", ".7z", ".tar", ".gz")

# ZIP dosyasının kendisi için üst boyut sınırı: 1 GiB
MAX_ARCHIVE_SIZE = 1024 * 1024 * 1024

# Merkezi dizin okunduktan sonra uygulanacak sınır
MAX_METADATA_ENTRIES = 10_000


def analyze_zip(file_path):
    """ZIP dosyasını çıkartmadan metadata üzerinden analiz eder."""

    path = Path(file_path)

    report = {
        "file_name": path.name,
        "status": "ERROR",
        "risk_level": "UNKNOWN",
        "total_files": 0,
        "compressed_size": 0,
        "uncompressed_size": 0,
        "compression_ratio": 0,
        "nested_archives": [],
        "warnings": [],
        "error": None,
    }

    if not path.is_file():
        report["error"] = "Dosya bulunamadı."
        return report

    try:
        # ZIP açılmadan önce arşivin kendi boyutunu kontrol et.
        archive_size = path.stat().st_size

        if archive_size > MAX_ARCHIVE_SIZE:
            report["risk_level"] = "HIGH"
            report["warnings"].append(
                "Arşiv dosyasının boyutu izin verilen sınırı aşıyor."
            )
            report["error"] = "Arşiv boyutu sınırı aşıldı."
            return report

        with zipfile.ZipFile(path, "r") as archive:
            entries = archive.infolist()

            # Metadata belleğe alındıktan sonra sayıyı kontrol eder.
            # Bu kontrol tek başına bellek tüketimini engellemez.
            if len(entries) > MAX_METADATA_ENTRIES:
                report["risk_level"] = "HIGH"
                report["warnings"].append(
                    "Arşivde çok fazla kayıt bulunuyor."
                )
                report["error"] = "Arşivdeki kayıt sayısı sınırı aşıldı."
                return report

            files = [
                entry for entry in entries
                if not entry.is_dir()
            ]

            total_compressed = sum(
                entry.compress_size for entry in files
            )
            total_uncompressed = sum(
                entry.file_size for entry in files
            )
            max_file_size = max(
                (entry.file_size for entry in files),
                default=0,
            )

            nested_archives = [
                entry.filename
                for entry in files
                if entry.filename.lower().endswith(
                    ARCHIVE_EXTENSIONS
                )
            ]

            risk = evaluate_archive(
                total_compressed_size=total_compressed,
                total_uncompressed_size=total_uncompressed,
                file_count=len(files),
                max_single_file_size=max_file_size,
                nested_archive_count=len(nested_archives),
            )

            report.update({
                "status": "OK",
                "risk_level": risk["risk_level"],
                "total_files": len(files),
                "compressed_size": total_compressed,
                "uncompressed_size": total_uncompressed,
                "compression_ratio": risk["compression_ratio"],
                "nested_archives": nested_archives,
                "warnings": risk["warnings"],
            })

    except (
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        OSError,
        ValueError,
    ) as error:
        report["error"] = f"Arşiv okunamadı: {error}"

    return report
