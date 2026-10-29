
import zipfile
from collections import Counter
from pathlib import Path

from zip_analyzer.rules import evaluate_archive

ARCHIVE_EXTENSIONS = (".zip", ".rar", ".7z", ".tar", ".gz")
MAX_ARCHIVE_SIZE = 1024 * 1024 * 1024
MAX_METADATA_ENTRIES = 10_000


def is_suspicious_path(filename):
    """Şüpheli arşiv içi yolları belirler."""
    normalized = filename.replace("\\", "/")
    parts = normalized.split("/")

    return (
        normalized.startswith("/")
        or any(part == ".." for part in parts)
        or (len(normalized) >= 2 and normalized[1] == ":")
        or "\x00" in normalized
    )


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
        "file_types": {},
        "nested_archives": [],
        "suspicious_paths": [],
        "warnings": [],
        "error": None,
    }

    if not path.is_file():
        report["error"] = "Dosya bulunamadı."
        return report

    try:
        if path.stat().st_size > MAX_ARCHIVE_SIZE:
            report["risk_level"] = "HIGH"
            report["warnings"].append(
                "Arşiv dosyasının boyutu izin verilen sınırı aşıyor."
            )
            report["error"] = "Arşiv boyutu sınırı aşıldı."
            return report

        with zipfile.ZipFile(path, "r") as archive:
            entries = archive.infolist()

            if len(entries) > MAX_METADATA_ENTRIES:
                report["risk_level"] = "HIGH"
                report["warnings"].append(
                    "Arşivde çok fazla kayıt bulunuyor."
                )
                report["error"] = "Arşivdeki kayıt sayısı sınırı aşıldı."
                return report

            files = [entry for entry in entries if not entry.is_dir()]

            suspicious_paths = [
                entry.filename
                for entry in files
                if is_suspicious_path(entry.filename)
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
                if entry.filename.lower().endswith(ARCHIVE_EXTENSIONS)
            ]

            file_types = Counter(
                Path(entry.filename).suffix.lower() or "[uzantısız]"
                for entry in files
            )

            risk = evaluate_archive(
                total_compressed_size=total_compressed,
                total_uncompressed_size=total_uncompressed,
                file_count=len(files),
                max_single_file_size=max_file_size,
                nested_archive_count=len(nested_archives),
            )

            warnings = list(risk["warnings"])

            if suspicious_paths:
                warnings.append(
                    "Şüpheli dosya yolu bulundu: "
                    + ", ".join(suspicious_paths[:5])
                )

            report.update({
                "status": "OK",
                "risk_level": (
                    "HIGH"
                    if suspicious_paths
                    else risk["risk_level"]
                ),
                "total_files": len(files),
                "compressed_size": total_compressed,
                "uncompressed_size": total_uncompressed,
                "compression_ratio": risk["compression_ratio"],
                "file_types": dict(sorted(file_types.items())),
                "nested_archives": nested_archives,
                "suspicious_paths": suspicious_paths,
                "warnings": warnings,
            })

    except (
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        OSError,
        ValueError,
        RuntimeError,
        EOFError,
    ) as error:
        report["error"] = f"Arşiv okunamadı: {error}"

    return report
