
# zip_analyzer/rules.py

# ZIP bombası tespitinde kullanılacak başlangıç eşikleri.
# Bu değerler daha sonra testlerle iyileştirilebilir.

MAX_TOTAL_UNCOMPRESSED_SIZE = 500 * 1024 * 1024  # 500 MiB
MAX_SINGLE_FILE_SIZE = 200 * 1024 * 1024  # 200 MiB
MAX_FILE_COUNT = 10_000
MAX_COMPRESSION_RATIO = 100


def calculate_compression_ratio(compressed_size, uncompressed_size):
    """Sıkıştırılmış ve açılmış boyutlardan oranı hesaplar."""

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
    """Arşiv bilgilerine göre risk seviyesini değerlendirir."""

    values = (
        total_compressed_size,
        total_uncompressed_size,
        file_count,
        max_single_file_size,
        nested_archive_count,
    )

    if any(value < 0 for value in values):
        raise ValueError("Boyutlar ve sayılar negatif olamaz.")

    warnings = []

    ratio = calculate_compression_ratio(
        total_compressed_size,
        total_uncompressed_size,
    )

    high_risk = False

    if total_uncompressed_size > MAX_TOTAL_UNCOMPRESSED_SIZE:
        warnings.append("Toplam açılmış boyut sınırı aşıldı.")
        high_risk = True

    if file_count > MAX_FILE_COUNT:
        warnings.append("Dosya sayısı sınırı aşıldı.")
        high_risk = True

    if max_single_file_size > MAX_SINGLE_FILE_SIZE:
        warnings.append("Tek dosyanın açılmış boyutu çok büyük.")
        high_risk = True

    if ratio > MAX_COMPRESSION_RATIO:
        warnings.append("Sıkıştırma oranı çok yüksek.")
        high_risk = True

    if nested_archive_count > 0:
        warnings.append("İç içe arşiv bulundu; ayrıca incelenmeli.")

    if high_risk:
        risk_level = "HIGH"
    elif warnings:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_level": risk_level,
        "compression_ratio": (
            round(ratio, 2) if ratio != float("inf") else "infinite"
        ),
        "warnings": warnings,
    }
