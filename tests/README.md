# Güvenli Arşiv Analizcisi - ZIP Analiz Motoru

ZIP arşivlerini **diske çıkarmadan**, sadece başlık (metadata) üzerinden analiz ederek zip bombası ve şüpheli içerikleri tespit eden savunma odaklı bir araçtır.

## Özellikler

- Sıkıştırma oranı analizi (toplam ve dosya başına)
- Toplam boyut ve dosya sayısı limitleri
- Özyinelemeli iç içe arşiv analizi (derinlik limitli)
- Çakışan giriş (overlap bomb) tespiti
- Zip Slip (path traversal) tespiti
- Şüpheli ve çift uzantılı dosya tespiti
- Magic bytes ile gizlenmiş çalıştırılabilir dosya tespiti
- Şifreli giriş ve sembolik bağlantı tespiti
- SHA-256 hash çıkarma (bellekte, parça parça)
- Risk skoru (0-100) ve analiz süresi

## Kurulum

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Kullanım

```powershell
python tests/make_samples.py              # test zip'lerini üretir
python main.py samples/normal.zip --pretty
python main.py samples/yuksek_oran.zip --summary
python benchmark.py samples/yuksek_oran.zip
python -m pytest
```

## Python'dan kullanım

```python
from zip_analyzer.analyzer import analyze_zip

report = analyze_zip("dosya.zip")
print(report["risk_level"], report["risk_score"])
```

Dönen sözlükteki başlıca alanlar: `risk_level` (LOW/MEDIUM/HIGH), `risk_score` (0-100), `warnings`, `file_hashes`, `analysis_time_ms`.

## Karşılaştırma (200 MB'lık zip bombası)

| | Bu proje | Naif `extractall` |
|---|---|---|
| Süre | 46.6 ms | 775.3 ms |
| Diske yazılan veri | 0 | ~200 MB |
| Sonuç | HIGH (tespit edildi) | Bombayı açtı |

## Sınırlamalar

- Şifreli arşivlerin içeriği okunamaz.
- Şu an sadece ZIP desteklenir (.7z/.rar planlanıyor).
- Statik kontroller şüphe işareti verir, zararlı olduğunu kanıtlamaz; kesin karar hash'in VirusTotal eşleşmesine ve YARA kurallarına bağlıdır.