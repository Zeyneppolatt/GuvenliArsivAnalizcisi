
from zip_analyzer.rules import (
    calculate_compression_ratio,
    evaluate_archive,
)


def test_compression_ratio():
    assert calculate_compression_ratio(100, 500) == 5


def test_zero_compressed_size():
    assert calculate_compression_ratio(0, 100) == float("inf")
    assert calculate_compression_ratio(0, 0) == 0.0


def test_negative_size_rejected():
    try:
        calculate_compression_ratio(-1, 100)
    except ValueError:
        pass
    else:
        raise AssertionError("Negatif boyut kabul edilmemeliydi.")


def test_high_risk_archive():
    result = evaluate_archive(
        total_compressed_size=1000,
        total_uncompressed_size=600 * 1024 * 1024,
        file_count=10,
        max_single_file_size=1000,
    )
    assert result["risk_level"] == "HIGH"


def test_high_compression_ratio():
    result = evaluate_archive(
        total_compressed_size=100,
        total_uncompressed_size=20_000,
        file_count=1,
        max_single_file_size=20_000,
    )
    assert result["risk_level"] == "HIGH"
    assert "Sıkıştırma oranı çok yüksek." in result["warnings"]


def test_nested_archive_medium_risk():
    result = evaluate_archive(
        total_compressed_size=1000,
        total_uncompressed_size=2000,
        file_count=2,
        max_single_file_size=1000,
        nested_archive_count=1,
    )
    assert result["risk_level"] == "MEDIUM"
    assert "İç içe arşiv bulundu; ayrıca incelenmeli." in result["warnings"]


def test_normal_archive():
    result = evaluate_archive(
        total_compressed_size=1000,
        total_uncompressed_size=2000,
        file_count=3,
        max_single_file_size=1000,
    )
    assert result["risk_level"] == "LOW"
    assert result["warnings"] == []


def test_negative_values_rejected():
    try:
        evaluate_archive(
            total_compressed_size=100,
            total_uncompressed_size=200,
            file_count=-1,
            max_single_file_size=100,
        )
    except ValueError:
        pass
    else:
        raise AssertionError("Negatif dosya sayısı kabul edilmemeliydi.")
