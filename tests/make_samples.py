import zipfile, os

os.makedirs("samples", exist_ok=True)

# 1) Normal zip
with zipfile.ZipFile("samples/normal.zip", "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("merhaba.txt", "Merhaba dunya! " * 100)

# 2) Yuksek oranli zip (200 MB sifir)
with zipfile.ZipFile("samples/yuksek_oran.zip", "w", zipfile.ZIP_DEFLATED) as z:
    with z.open("sifirlar.bin", "w", force_zip64=True) as f:
        for _ in range(200):
            f.write(b"\x00" * (1024 * 1024))

# 3) Ic ice zip (3 seviye)
inner = "samples/yuksek_oran.zip"
for i in range(1, 4):
    out = f"samples/ic_ice_{i}.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(inner, f"katman{i}.zip")
    inner = out

# 4) Zip Slip ornegi
with zipfile.ZipFile("samples/zip_slip.zip", "w") as z:
    z.writestr("../../evil.txt", "test")

# 5) Cift uzantili dosya
with zipfile.ZipFile("samples/cift_uzanti.zip", "w") as z:
    z.writestr("fatura.pdf.exe", "sahte icerik")

print("Test zip'leri samples/ klasorune uretildi.")