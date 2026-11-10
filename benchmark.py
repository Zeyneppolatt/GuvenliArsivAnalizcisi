import sys
import time
import tracemalloc
import zipfile
import tempfile

from zip_analyzer.analyzer import analyze_zip


def measure_ours(path):
    tracemalloc.start()
    start = time.perf_counter()
    report = analyze_zip(path)
    elapsed = time.perf_counter() - start
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return elapsed, peak, report["risk_level"]


def measure_naive(path):
    tracemalloc.start()
    start = time.perf_counter()
    with tempfile.TemporaryDirectory() as tmp:
        with zipfile.ZipFile(path) as z:
            z.extractall(tmp)
    elapsed = time.perf_counter() - start
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return elapsed, peak


if __name__ == "__main__":
    path = sys.argv[1]

    t1, m1, risk = measure_ours(path)
    print(f"Bizim yontem : {t1 * 1000:8.1f} ms | RAM zirvesi {m1 / 1024:10.1f} KB | Sonuc: {risk}")

    t2, m2 = measure_naive(path)
    print(f"Naif extract : {t2 * 1000:8.1f} ms | RAM zirvesi {m2 / 1024:10.1f} KB | Diske yazilan veri")