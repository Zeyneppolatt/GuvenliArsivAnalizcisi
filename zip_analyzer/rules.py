
from pathlib import Path

MAX_TOTAL_UNCOMPRESSED_SIZE = 500 * 1024 * 1024
MAX_SINGLE_FILE_SIZE = 200 * 1024 * 1024
MAX_FILE_COUNT = 10_000
MAX_COMPRESSION_RATIO = 100

SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".bat",
    ".cmd",
    ".scr",
    ".ps1",
    ".vbs",
    ".js",
    ".jse",
    ".wsf",
    ".msi",
    ".com",
    ".hta",
    ".dll",
    ".pif",
}


def calculate_compression_ratio(compressed_size, uncompressed_size):
    """Sıkıştırma oranını hesaplar."""
    if compressed_size < 0 or uncompressed_size < 0:
        raise ValueError("Dosya boyutları negatif olamaz.")

    if compressed_size == 0:
        return float("inf") if uncompressed_size > 0 else 0

    return uncompressed_size / compressed_size


def evaluate_archive(
    total_compressed_size,
    total_uncompressed_size,
    file_count,
    max_single_file_size,
    nested_archive_count=0,
):
    """Arşivin genel risk seviyesini değerlendirir."""
    if min(
        total_compressed_size,
        total_uncompressed_size,
        file_count,
        max_single_file_size,
        nested_archive_count,
    ) < 0:
        raise ValueError("Değerler negatif olamaz.")

    ratio = calculate_compression_ratio(
        total_compressed_size,
        total_uncompressed_size,
    )

    warnings = []
    risk_level = "LOW"

    if total_uncompressed_size > MAX_TOTAL_UNCOMPRESSED_SIZE:
        warnings.append("Toplam açılmış boyut çok yüksek.")
        risk_level = "HIGH"

    if max_single_file_size > MAX_SINGLE_FILE_SIZE:
        warnings.append("Tek bir dosyanın boyutu çok yüksek.")
        risk_level = "HIGH"

    if file_count > MAX_FILE_COUNT:
        warnings.append("Arşivde çok fazla dosya bulunuyor.")
        risk_level = "HIGH"

    if ratio > MAX_COMPRESSION_RATIO:
        warnings.append("Sıkıştırma oranı çok yüksek.")
        risk_level = "HIGH"

    if nested_archive_count > 0:
        warnings.append(
            "İç içe arşiv bulundu; ayrıca incelenmeli."
        )
        if risk_level != "HIGH":
            risk_level = "MEDIUM"

    return {
        "risk_level": risk_level,
        "compression_ratio": ratio,
        "warnings": warnings,
    }


def evaluate_special_entries(encrypted_count, symlink_count):
    """Şifreli dosya ve sembolik bağlantı risklerini değerlendirir."""
    if encrypted_count < 0 or symlink_count < 0:
        raise ValueError("Dosya sayıları negatif olamaz.")

    warnings = []
    risk_level = "LOW"

    if encrypted_count > 0:
        warnings.append(
            f"Arşivde {encrypted_count} şifrelenmiş dosya bulundu."
        )
        risk_level = "MEDIUM"

    if symlink_count > 0:
        warnings.append(
            f"Arşivde {symlink_count} sembolik bağlantı bulundu."
        )
        risk_level = "HIGH"

    return {
        "risk_level": risk_level,
        "warnings": warnings,
    }


def evaluate_suspicious_files(filenames):
    """Şüpheli uzantıları ve çift uzantılı dosyaları tespit eder."""
    suspicious_files = []
    double_extension_files = []
    warnings = []

    for filename in filenames:
        suffixes = [
            suffix.lower()
            for suffix in Path(filename).suffixes
        ]

        if not suffixes:
            continue

        if suffixes[-1] in SUSPICIOUS_EXTENSIONS:
            suspicious_files.append(filename)

        if (
            len(suffixes) >= 2
            and suffixes[-1] in SUSPICIOUS_EXTENSIONS
        ):
            double_extension_files.append(filename)

    if suspicious_files:
        warnings.append(
            f"{len(suspicious_files)} şüpheli uzantılı dosya bulundu."
        )

    if double_extension_files:
        warnings.append(
            f"{len(double_extension_files)} çift uzantılı dosya bulundu."
        )

    risk_level = "LOW"

    if suspicious_files:
        risk_level = "MEDIUM"

    if double_extension_files:
        risk_level = "HIGH"

    return {
        "risk_level": risk_level,
        "suspicious_files": suspicious_files,
        "double_extension_files": double_extension_files,
        "warnings": warnings,
    }
