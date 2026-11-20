import hashlib
import os
import zipfile
from pathlib import Path
import requests

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

DEFAULT_YARA_PATH = Path(__file__).parent / "rules.yar"
MAX_YARA_SCAN_SIZE = 20 * 1024 * 1024  # Güvenli modda dosya başı maks 20 MB YARA taraması
VT_API_URL = "https://www.virustotal.com/api/v3/files/"


def calculate_archive_sha256(file_path):
    """Arşiv dosyasının kendisinin SHA-256 hash değerini hesaplar."""
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha.update(chunk)
    return sha.hexdigest()


def query_virustotal(file_hash, api_key):
    """VirusTotal API v3 üzerinden SHA-256 hash sorgular (dosyayı yüklemez)."""
    if not api_key:
        return {"status": "SKIPPED", "reason": "API anahtarı verilmedi."}

    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(f"{VT_API_URL}{file_hash}", headers=headers, timeout=10)
        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            return {
                "status": "FOUND",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
            }
        if resp.status_code == 404:
            return {"status": "NOT_FOUND", "message": "VirusTotal kaydı bulunamadı."}
        return {"status": "ERROR", "message": f"HTTP {resp.status_code}"}
    except requests.RequestException as exc:
        return {"status": "ERROR", "message": str(exc)}


def scan_archive_with_yara(file_path, skip_names=None, safe_mode=True, rule_path=DEFAULT_YARA_PATH):
    """Arşiv içindeki dosyaları diske çıkarmadan RAM üzerinde YARA ile tarar."""
    if not YARA_AVAILABLE:
        return {"status": "UNAVAILABLE", "matches": [], "error": "yara-python yüklü değil."}

    if not Path(rule_path).is_file():
        return {"status": "ERROR", "matches": [], "error": f"YARA kural dosyası bulunamadı: {rule_path}"}

    skip_names = set(skip_names or [])
    rules = yara.compile(filepath=str(rule_path))
    matches = []
    skipped_safe_mode = []

    try:
        with zipfile.ZipFile(file_path, "r") as archive:
            for entry in archive.infolist():
                if entry.is_dir():
                    continue
                if entry.flag_bits & 0x1:  # Şifreli dosya
                    continue
                if entry.filename in skip_names:
                    skipped_safe_mode.append(entry.filename)
                    continue

                # Güvenli Mod Koruması: Devasa dosyaları RAM'e okuma!
                if safe_mode and entry.file_size > MAX_YARA_SCAN_SIZE:
                    skipped_safe_mode.append(entry.filename)
                    continue

                try:
                    with archive.open(entry, "r") as handle:
                        data = handle.read(MAX_YARA_SCAN_SIZE + 1)
                    if safe_mode and len(data) > MAX_YARA_SCAN_SIZE:
                        skipped_safe_mode.append(entry.filename)
                        continue

                    hits = rules.match(data=data)
                    for hit in hits:
                        matches.append({
                            "file_name": entry.filename,
                            "rule": hit.rule,
                            "severity": hit.meta.get("severity", "MEDIUM"),
                            "description": hit.meta.get("description", ""),
                        })
                except (OSError, RuntimeError, ValueError, EOFError, zipfile.BadZipFile):
                    continue
    except (zipfile.BadZipFile, OSError) as exc:
        return {"status": "ERROR", "matches": [], "error": str(exc)}

    return {
        "status": "OK",
        "matches": matches,
        "skipped_safe_mode": skipped_safe_mode,
    }


def run_threat_intelligence(file_path, file_hashes, skip_names=None, safe_mode=True, vt_api_key=None):
    """
    Tehdit istihbaratı katmanını çalıştırır:
    1. Arşivin SHA-256 hash'ini ve VirusTotal sonucunu alır.
    2. YARA kurallarıyla bellek içi (in-memory) imza taraması yapar.
    3. YARA eşleşmesi olan veya şüpheli iç dosyaların hash'lerini VirusTotal'de sorgular.
    """
    api_key = vt_api_key or os.getenv("VT_API_KEY")
    archive_sha256 = calculate_archive_sha256(file_path)
    archive_vt = query_virustotal(archive_sha256, api_key)

    yara_result = scan_archive_with_yara(
        file_path=file_path,
        skip_names=skip_names,
        safe_mode=safe_mode,
    )

    # API kotasını korumak için: YARA eşleşmesi olan iç dosyaların hash'lerini VT'ye sor
    yara_flagged_files = {m["file_name"] for m in yara_result.get("matches", [])}
    inner_vt_results = []

    if api_key and yara_flagged_files:
        for item in file_hashes:
            if item["name"] in yara_flagged_files:
                vt_res = query_virustotal(item["sha256"], api_key)
                inner_vt_results.append({
                    "file_name": item["name"],
                    "sha256": item["sha256"],
                    "vt_result": vt_res,
                })

    vt_malicious_total = archive_vt.get("malicious", 0) + sum(
        entry["vt_result"].get("malicious", 0) for entry in inner_vt_results
    )

    return {
        "safe_mode": safe_mode,
        "archive_sha256": archive_sha256,
        "archive_vt": archive_vt,
        "yara_scan": yara_result,
        "inner_vt_results": inner_vt_results,
        "vt_malicious_count": vt_malicious_total,
        "yara_match_count": len(yara_result.get("matches", [])),
    }