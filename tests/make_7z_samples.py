import os
import py7zr

os.makedirs("samples", exist_ok=True)

# 1) Normal 7z
with py7zr.SevenZipFile("samples/normal.7z", "w") as z:
    z.writestr("Merhaba dunya! " * 100, "merhaba.txt")

# 2) Yuksek oranli 7z (100 MB sifir)
zeros = "samples/_zeros.bin"
with open(zeros, "wb") as f:
    for _ in range(100):
        f.write(b"\x00" * (1024 * 1024))

with py7zr.SevenZipFile("samples/yuksek_oran.7z", "w") as z:
    z.write(zeros, "sifirlar.bin")

os.remove(zeros)

# 3) Cift uzantili dosya
with py7zr.SevenZipFile("samples/cift_uzanti.7z", "w") as z:
    z.writestr("sahte icerik", "fatura.pdf.exe")

print("7z ornekleri samples/ klasorune uretildi.")