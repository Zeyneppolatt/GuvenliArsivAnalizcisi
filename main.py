
import argparse
import json
import sys
from pathlib import Path

from zip_analyzer.analyzer import analyze_zip


def print_summary(report):
    print(f"Dosya: {report['file_name']}")
    print(f"Durum: {report['status']}")
    print(f"Risk seviyesi: {report['risk_level']}")
    print(f"Dosya sayısı: {report['total_files']}")
    print(f"Açılmış boyut: {report['uncompressed_size']} bayt")
    print(f"Sıkıştırılmış boyut: {report['compressed_size']} bayt")
    print(f"Sıkıştırma oranı: {report['compression_ratio']:.2f}")

    print("\nDosya türleri:")
    if report["file_types"]:
        for extension, count in report["file_types"].items():
            print(f"  {extension}: {count}")
    else:
        print("  Dosya türü bulunamadı.")

    print(f"\nİç içe arşiv sayısı: {len(report['nested_archives'])}")
    print(f"Şüpheli yol sayısı: {len(report['suspicious_paths'])}")

    print("\nUyarılar:")
    if report["warnings"]:
        for warning in report["warnings"]:
            print(f"  - {warning}")
    else:
        print("  Uyarı yok.")

    if report["error"]:
        print(f"\nHata: {report['error']}")


def analyze_path(target):
    """Bir ZIP dosyasını veya klasördeki ZIP dosyalarını analiz eder."""
    path = Path(target)

    if path.is_file():
        return [analyze_zip(path)]

    if path.is_dir():
        zip_files = sorted(
            item for item in path.iterdir()
            if item.is_file() and item.suffix.lower() == ".zip"
        )
        return [analyze_zip(item) for item in zip_files]

    return [{
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
        "error": "Dosya veya klasör bulunamadı.",
    }]


def main():
    parser = argparse.ArgumentParser(
        description="ZIP arşivlerini çıkartmadan analiz eder."
    )
    parser.add_argument(
        "path",
        help="Analiz edilecek ZIP dosyası veya ZIP dosyalarını içeren klasör",
    )
    parser.add_argument(
        "--output", "-o",
        help="JSON raporunun kaydedileceği dosya",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="JSON çıktısını okunabilir biçimde göster",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Kısa analiz özeti göster",
    )

    args = parser.parse_args()
    reports = analyze_path(args.path)
    is_directory = Path(args.path).is_dir()

    if args.summary:
        for index, report in enumerate(reports):
            if index:
                print("\n" + "-" * 40 + "\n")
            print_summary(report)

        counts = {}
        for report in reports:
            level = report["risk_level"]
            counts[level] = counts.get(level, 0) + 1

        print("\n===== TOPLU ANALİZ ÖZETİ =====")
        print(f"Toplam arşiv: {len(reports)}")
        for level in ("HIGH", "MEDIUM", "LOW", "UNKNOWN"):
            if counts.get(level):
                print(f"{level}: {counts[level]}")

    else:
        output_data = reports if is_directory else reports[0]
        json_output = json.dumps(
            output_data,
            ensure_ascii=False,
            indent=2 if args.pretty or args.output else None,
        )

        if not args.output:
            print(json_output)

    if args.output:
        try:
            output_path = Path(args.output)
            output_data = reports if is_directory else reports[0]

            output_path.write_text(
                json.dumps(
                    output_data,
                    ensure_ascii=False,
                    indent=2,
                ) + "\n",
                encoding="utf-8",
            )

            print(f"Rapor kaydedildi: {output_path}")

        except OSError as error:
            print(
                f"Rapor dosyası kaydedilemedi: {error}",
                file=sys.stderr,
            )
            return 2

    return 0 if all(
        report["status"] == "OK" for report in reports
    ) else 1


if __name__ == "__main__":
    sys.exit(main())
