
# Güvenli Arşiv Analizcisi

ZIP arşivlerini herhangi bir dosyayı dışarı çıkarmadan analiz eden, potansiyel güvenlik risklerini tespit eden Python tabanlı bir güvenlik aracıdır.

## Proje Hakkında

Güvenli Arşiv Analizcisi, ZIP dosyalarının içeriğini çıkartmadan metadata üzerinden inceleyerek şüpheli durumları belirlemek amacıyla geliştirilmiştir.

Özellikle zararlı olabilecek dosya uzantıları, yanıltıcı dosya adları, aşırı sıkıştırma oranları ve iç içe arşivler analiz edilir.

## Özellikler

- ZIP arşivlerini çıkartmadan analiz etme
- Toplam sıkıştırılmış ve açılmış boyut hesaplama
- Sıkıştırma oranı kontrolü
- Dosya sayısı ve boyut sınırı kontrolü
- Şüpheli dosya yolu tespiti
- Şifreli dosya tespiti
- Sembolik bağlantı tespiti
- Şüpheli dosya uzantılarının belirlenmesi
- Çift uzantılı dosya tespiti
- İç içe ZIP arşivlerini bir seviye derinlikte analiz etme
- JSON formatında rapor oluşturma
- Klasör içerisindeki ZIP dosyalarını toplu analiz etme
- Otomatik testlerle doğrulama

## Kullanılan Teknolojiler

- Python
- zipfile
- pathlib
- argparse
- json
- pytest

## Proje Yapısı

```text
GuvenliArsivAnalizcisi/
│
├── main.py
├── zip_analyzer/
│   ├── __init__.py
│   ├── analyzer.py
│   └── rules.py
│
├── tests/
│   ├── test_analyzer.py
│   └── README.md
│
├── .gitignore
├── requirements.txt
└── README.md
```

## Kurulum

Projeyi bilgisayarınıza indirin:

```bash
git clone https://github.com/Zeyneppolatt/GuvenliArsivAnalizcisi.git
cd GuvenliArsivAnalizcisi
```

Sanal ortam oluşturun:

```bash
python -m venv .venv
```

Sanal ortamı etkinleştirin:

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Gerekli paketleri yükleyin:

```bash
pip install -r requirements.txt
```

## Kullanım

Tek bir ZIP dosyasını analiz etmek:

```bash
python main.py arsiv.zip
```

Okunabilir JSON çıktısı almak:

```bash
python main.py arsiv.zip --pretty
```

Kısa analiz özeti görüntülemek:

```bash
python main.py arsiv.zip --summary
```

JSON raporunu dosyaya kaydetmek:

```bash
python main.py arsiv.zip --output rapor.json
```

Bir klasördeki ZIP dosyalarını toplu analiz etmek:

```bash
python main.py arsivler/ --summary --output rapor.json
```

## Risk Seviyeleri

| Risk Seviyesi | Açıklama |
|---|---|
| LOW | Belirlenen kontrollerde önemli bir risk bulunmadı. |
| MEDIUM | İncelenmesi gereken şüpheli durumlar bulundu. |
| HIGH | Yüksek riskli özellikler tespit edildi. |
| UNKNOWN | Analiz tamamlanamadı. |

## Testler

Testleri çalıştırmak için:

```bash
python -m pytest -q
```

## Güvenlik Notu

Bu araç ZIP arşivlerini çıkartmaz ve içindeki dosyaları çalıştırmaz. Analiz işlemleri arşiv metadata bilgileri ve sınırlı boyutta belleğe alınan iç ZIP verileri üzerinden gerçekleştirilir.

Tespit edilen şüpheli uzantılar tek başına bir dosyanın zararlı olduğunu kanıtlamaz. Araç, güvenlik incelemesine yardımcı olmak amacıyla geliştirilmiştir.

## Geliştirici

**Zeynep Polat**

GitHub: https://github.com/Zeyneppolatt
