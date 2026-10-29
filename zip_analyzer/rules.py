
MAX_TOTAL_UNCOMPRESSED_SIZE = 500 * 1024 * 1024
MAX_SINGLE_FILE_SIZE = 200 * 1024 * 1024
MAX_FILE_COUNT = 10_000
MAX_COMPRESSION_RATIO = 100


def calculate_compression_ratio(compressed_size, uncompressed_size):
    """Sıkıştırma oranını güvenli şekilde hesaplar."""
    if compressed_size < 0 or uncompressed_size < 0:
        raise ValueError("Dosya boyutları negatif olamaz.")

    if compressed_size == 0:
        return float("inf") if uncompressed_size > 0 else 0.0

    return uncompressed_size / compressed_size


def evaluate_archive(
    total_compressed_size,
    total_uncompressed_size,
    file_count,
    max_single_file_size,
    nested_archive_count=0,
):
    """Arşiv metadata bilgilerine göre risk seviyesini belirler."""
    values = (
        total_compressed_size,
        total_uncompressed_size,
        file_count,
        max_single_file_size,
        nested_archive_count,
    )

    if any(value < 0 for value in values):
        raise ValueError("Değerler negatif olamaz.")

    ratio = calculate_compression_ratio(
        total_compressed_size,
        total_uncompressed_size,
    )

    warnings = []
    risk_level = "LOW"

    if total_uncompressed_size > MAX_TOTAL_UNCOMPRESSED_SIZE:
        warnings.append("Toplam açılmış boyut sınırı aşıldı.")
        risk_level = "HIGH"

    if file_count > MAX_FILE_COUNT:
        warnings.append("Dosya sayısı sınırı aşıldı.")
        risk_level = "HIGH"

    if max_single_file_size > MAX_SINGLE_FILE_SIZE:
        warnings.append("Tek dosyanın açılmış boyut sınırı aşıldı.")
        risk_level = "HIGH"

    if ratio > MAX_COMPRESSION_RATIO:
        warnings.append("Sıkıştırma oranı çok yüksek.")
        risk_level = "HIGH"

    if nested_archive_count > 0:
        warnings.append("İç içe arşiv bulundu; ayrıca incelenmeli.")
        if risk_level == "LOW":
            risk_level = "MEDIUM"

    return {
        "risk_level": risk_level,
        "compression_ratio": ratio,
        "warnings": warnings,
    }
