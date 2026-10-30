
import io
import zipfile
from collections import Counter
from pathlib import Path

from zip_analyzer.rules import (
    evaluate_archive,
    evaluate_special_entries,
    evaluate_suspicious_files,
)

ARCHIVE_EXTENSIONS = (".zip", ".rar", ".7z", ".tar", ".gz")
MAX_ARCHIVE_SIZE = 1024 * 1024 * 1024
MAX_METADATA_ENTRIES = 10_000
MAX_NESTED_ARCHIVE_SIZE = 50 * 1024 * 1024


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


def analyze_nested_zip(archive_data, filename):
    """Bellekteki iç ZIP dosyasını çıkartmadan analiz eder."""
    result = {
        "file_name": filename,
        "status": "ERROR",
        "risk_level": "UNKNOWN",
        "total_files": 0,
        "suspicious_files": [],
        "double_extension_files": [],
        "suspicious_paths": [],
        "warnings": [],
        "error": None,
    }

    try:
        with zipfile.ZipFile(io.BytesIO(archive_data), "r") as nested:
            entries = nested.infolist()

            if len(entries) > MAX_METADATA_ENTRIES:
                result["risk_level"] = "HIGH"
                result["error"] = "İç arşivdeki kayıt sayısı sınırı aşıldı."
                return result

            files = [
                entry for entry in entries
                if not entry.is_dir()
            ]

            filenames = [entry.filename for entry in files]

            suspicious_paths = [
                name for name in filenames
                if is_suspicious_path(name)
            ]

            suspicious_risk = evaluate_suspicious_files(filenames)

            encrypted_count = sum(
                1 for entry in files
                if entry.flag_bits & 0x1
            )

            symlink_count = sum(
                1 for entry in files
                if ((entry.external_attr >> 16) & 0o170000) == 0o120000
            )

            special_risk = evaluate_special_entries(
                encrypted_count=encrypted_count,
                symlink_count=symlink_count,
            )

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

            nested_count = sum(
                1 for name in filenames
                if name.lower().endswith(ARCHIVE_EXTENSIONS)
            )

            archive_risk = evaluate_archive(
                total_compressed_size=total_compressed,
                total_uncompressed_size=total_uncompressed,
                file_count=len(files),
                max_single_file_size=max_file_size,
                nested_archive_count=nested_count,
            )

            warnings = list(archive_risk["warnings"])
            warnings.extend(special_risk["warnings"])
            warnings.extend(suspicious_risk["warnings"])

            if suspicious_paths:
                warnings.append("İç arşivde şüpheli dosya yolu bulundu.")

            risk_levels = [
                archive_risk["risk_level"],
                special_risk["risk_level"],
                suspicious_risk["risk_level"],
            ]

            if suspicious_paths:
                risk_levels.append("HIGH")

            if "HIGH" in risk_levels:
                final_risk = "HIGH"
            elif "MEDIUM" in risk_levels:
                final_risk = "MEDIUM"
            else:
                final_risk = "LOW"

            result.update({
                "status": "OK",
                "risk_level": final_risk,
                "total_files": len(files),
                "suspicious_files": suspicious_risk["suspicious_files"],
                "double_extension_files": suspicious_risk[
                    "double_extension_files"
                ],
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
        result["error"] = f"İç arşiv okunamadı: {error}"

    return result


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
        "nested_archive_reports": [],
        "suspicious_paths": [],
        "encrypted_files": [],
        "symlink_files": [],
        "suspicious_files": [],
        "double_extension_files": [],
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

            files = [
                entry for entry in entries
                if not entry.is_dir()
            ]

            filenames = [entry.filename for entry in files]

            suspicious_paths = [
                entry.filename
                for entry in files
                if is_suspicious_path(entry.filename)
            ]

            encrypted_files = [
                entry.filename
                for entry in files
                if entry.flag_bits & 0x1
            ]

            symlink_files = [
                entry.filename
                for entry in files
                if ((entry.external_attr >> 16) & 0o170000) == 0o120000
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
                if entry.filename.lower().endswith(".zip")
            ]

            nested_archive_reports = []

            for entry in files:
                if not entry.filename.lower().endswith(".zip"):
                    continue

                if entry.file_size > MAX_NESTED_ARCHIVE_SIZE:
                    nested_archive_reports.append({
                        "file_name": entry.filename,
                        "status": "SKIPPED",
                        "risk_level": "HIGH",
                        "error": "İç ZIP dosyası boyut sınırını aşıyor.",
                    })
                    continue

                try:
                    with archive.open(entry, "r") as nested_file:
                        nested_data = nested_file.read(
                            MAX_NESTED_ARCHIVE_SIZE + 1
                        )

                    if len(nested_data) > MAX_NESTED_ARCHIVE_SIZE:
                        nested_archive_reports.append({
                            "file_name": entry.filename,
                            "status": "SKIPPED",
                            "risk_level": "HIGH",
                            "error": "İç ZIP dosyası boyut sınırını aşıyor.",
                        })
                        continue

                    nested_report = analyze_nested_zip(
                        nested_data,
                        entry.filename,
                    )
                    nested_archive_reports.append(nested_report)

                except (
                    OSError,
                    RuntimeError,
                    ValueError,
                    EOFError,
                    zipfile.BadZipFile,
                ) as error:
                    nested_archive_reports.append({
                        "file_name": entry.filename,
                        "status": "ERROR",
                        "risk_level": "UNKNOWN",
                        "error": str(error),
                    })

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

            special_risk = evaluate_special_entries(
                encrypted_count=len(encrypted_files),
                symlink_count=len(symlink_files),
            )

            suspicious_risk = evaluate_suspicious_files(filenames)

            warnings = list(risk["warnings"])
            warnings.extend(special_risk["warnings"])
            warnings.extend(suspicious_risk["warnings"])

            if suspicious_paths:
                warnings.append(
                    "Şüpheli dosya yolu bulundu: "
                    + ", ".join(suspicious_paths[:5])
                )

            for nested_report in nested_archive_reports:
                if nested_report["risk_level"] == "HIGH":
                    warnings.append(
                        f"İç ZIP yüksek riskli: {nested_report['file_name']}"
                    )
                elif nested_report["risk_level"] == "MEDIUM":
                    warnings.append(
                        f"İç ZIP orta riskli: {nested_report['file_name']}"
                    )

            risk_levels = [
                risk["risk_level"],
                special_risk["risk_level"],
                suspicious_risk["risk_level"],
            ]

            if suspicious_paths:
                risk_levels.append("HIGH")

            if any(
                item["risk_level"] == "HIGH"
                for item in nested_archive_reports
            ):
                risk_levels.append("HIGH")
            elif any(
                item["risk_level"] == "MEDIUM"
                for item in nested_archive_reports
            ):
                risk_levels.append("MEDIUM")

            if "HIGH" in risk_levels:
                final_risk = "HIGH"
            elif "MEDIUM" in risk_levels:
                final_risk = "MEDIUM"
            else:
                final_risk = "LOW"

            report.update({
                "status": "OK",
                "risk_level": final_risk,
                "total_files": len(files),
                "compressed_size": total_compressed,
                "uncompressed_size": total_uncompressed,
                "compression_ratio": risk["compression_ratio"],
                "file_types": dict(sorted(file_types.items())),
                "nested_archives": nested_archives,
                "nested_archive_reports": nested_archive_reports,
                "suspicious_paths": suspicious_paths,
                "encrypted_files": encrypted_files,
                "symlink_files": symlink_files,
                "suspicious_files": suspicious_risk["suspicious_files"],
                "double_extension_files": suspicious_risk[
                    "double_extension_files"
                ],
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
