# Güvenli Arşiv Analizcisi

ZIP arşivlerini çıkartmadan analiz ederek olası güvenlik risklerini belirlemeyi amaçlayan Python tabanlı bir projedir.

## Özellikler

- ZIP dosyalarının metadata bilgilerinin incelenmesi
- Sıkıştırma oranının hesaplanması
- Toplam açılmış boyut ve dosya sayısı sınırlarının kontrolü
- Tek dosyanın açılmış boyutunun kontrolü
- İç içe arşivlerin tespit edilmesi
- Normal, orta riskli ve yüksek riskli arşivlerin sınıflandırılması
- Bozuk veya bulunamayan dosyalar için hata yönetimi
- Pytest ile otomatik testler

## Proje yapısı

```text
GuvenliArsivAnalizcisi/
├── zip_analyzer/
│   ├── analyzer.py
│   └── rules.py
├── tests/
│   ├── test_rules.py
│   └── test_analyzer.py
├── main.py
├── .gitignore
└── README.md
```

## Kurulum

Python ve Git kurulu olmalıdır.

Sanal ortam oluşturmak için:

```powershell
python -m venv .venv
```

Sanal ortamı etkinleştirmek için Windows PowerShell'de:

```powershell
.\.venv\Scripts\Activate.ps1
```

Test bağımlılığını yüklemek için:

```powershell
python -m pip install pytest
```

## Kullanım

Bir ZIP dosyasını analiz etmek için:

```powershell
python main.py ".\test.zip"
```

Analiz sonucu JSON formatında görüntülenir.

## Testler

Tüm otomatik testleri çalıştırmak için:

```powershell
python -m pytest -v
```

## Güvenlik notu

Bu proje geliştirme aşamasında bir prototiptir. Arşivler çıkartılmadan analiz edilse de bellek tüketimi ve kötü amaçlı arşivlere karşı tüm riskleri ortadan kaldırdığı garanti edilmez. Üretim ortamında kullanılmadan önce ek güvenlik kontrolleri ve kapsamlı testler gereklidir.