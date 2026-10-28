
# main.py

import json
import sys

from zip_analyzer.analyzer import analyze_zip


def main():
    if len(sys.argv) != 2:
        print("Kullanim: python main.py dosya.zip")
        return

    report = analyze_zip(sys.argv[1])
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
