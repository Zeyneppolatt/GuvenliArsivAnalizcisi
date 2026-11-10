import time
from collections import Counter
from pathlib import Path

import py7zr

from zip_analyzer.analyzer import calculate_risk_score, is_suspicious_path
from zip_analyzer.rules import evaluate_archive, evaluate_suspicious_files

MAX_ARCHIVE_SIZE = 1024 * 1024 * 1024
MAX_ENTRIES = 10_000


def analyze_7z(file_path):
    """7z arşivini çıkartmadan, sadece başlık bilgisiyle analiz eder."""
    start = time.perf_counter()
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
        "nested_archive_reports": [],
        "suspicious_paths": [],
        "encrypted_files": [],
        "symlink_files": [],
        "suspicious_files": [],
        "double_extension_files": [],
        "high_ratio_files": [],
        "overlapping_entries": [],
        "disguised_files": [],
        "file_hashes": [],
        "warnings": [],
        "error": None,
    }

    if not path.is_file():
        report["error"] = "Dosya bulunamadı."
        return report

    try:
        compressed_total = path.stat().st_size
        if compressed_total > MAX_ARCHIVE_SIZE:
            report["risk_level"] = "HIGH"
            report["error"] = "Arşiv boyutu sınırı aşıldı."
            return report

        with py7zr.SevenZipFile(path, "r") as archive:
            if archive.needs_password():
                report["status"] = "OK"
                report["risk_level"] = "MEDIUM"
                report["encrypted_files"] = ["[tüm arşiv şifreli]"]
                report["warnings"].append(
                    "Arşiv şifreli, içeriği analiz edilemedi."
                )
                report["analysis_time_ms"] = round(
                    (time.perf_counter() - start) * 1000, 1
                )
                report["risk_score"] = 10
                return report

            infos = archive.list()

        if len(infos) > MAX_ENTRIES:
            report["risk_level"] = "HIGH"
            report["error"] = "Arşivdeki kayıt sayısı sınırı aşıldı."
            return report

        files = [i for i in infos if not i.is_directory]
        filenames = [i.filename for i in files]
        uncompressed_total = sum(i.uncompressed or 0 for i in files)
        max_file = max((i.uncompressed or 0 for i in files), default=0)

        suspicious_paths = [
            n for n in filenames if is_suspicious_path(n)
        ]
        symlinks = [i.filename for i in files if i.is_symlink]
        nested = [
            n for n in filenames
            if n.lower().endswith((".zip", ".7z", ".rar", ".tar", ".gz"))
        ]

        risk = evaluate_archive(
            total_compressed_size=compressed_total,
            total_uncompressed_size=uncompressed_total,
            file_count=len(files),
            max_single_file_size=max_file,
            nested_archive_count=len(nested),
        )
        suspicious_risk = evaluate_suspicious_files(filenames)

        warnings = list(risk["warnings"]) + list(suspicious_risk["warnings"])
        if suspicious_paths:
            warnings.append(
                "Şüpheli dosya yolu bulundu: "
                + ", ".join(suspicious_paths[:5])
            )
        if symlinks:
            warnings.append(f"{len(symlinks)} sembolik bağlantı bulundu.")

        levels = [risk["risk_level"], suspicious_risk["risk_level"]]
        if suspicious_paths or symlinks:
            levels.append("HIGH")

        if "HIGH" in levels:
            final = "HIGH"
        elif "MEDIUM" in levels:
            final = "MEDIUM"
        else:
            final = "LOW"

        file_types = Counter(
            Path(n).suffix.lower() or "[uzantısız]" for n in filenames
        )

        report.update({
            "status": "OK",
            "risk_level": final,
            "total_files": len(files),
            "compressed_size": compressed_total,
            "uncompressed_size": uncompressed_total,
            "compression_ratio": risk["compression_ratio"],
            "file_types": dict(sorted(file_types.items())),
            "nested_archives": nested,
            "suspicious_paths": suspicious_paths,
            "symlink_files": symlinks,
            "suspicious_files": suspicious_risk["suspicious_files"],
            "double_extension_files": suspicious_risk[
                "double_extension_files"
            ],
            "warnings": warnings,
        })

    except Exception as error:  # py7zr birden fazla hata türü fırlatabilir
        report["error"] = f"Arşiv okunamadı: {error}"

    report["analysis_time_ms"] = round(
        (time.perf_counter() - start) * 1000, 1
    )
    report["risk_score"] = calculate_risk_score(report)
    return report
