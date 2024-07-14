#This python script design by Jivitesh & RAHUL Yadav
import pefile
import hashlib
import sys
from datetime import datetime
import re

def compute_hashes(file_path):
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
            sha256_hash.update(byte_block)

    return md5_hash.hexdigest(), sha256_hash.hexdigest()

def extract_strings(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    strings = set(re.findall(b'[\x20-\x7E]{5,}', data))  # Extract ASCII strings of length >= 5
    return list(map(lambda x: x.decode('ascii', errors='ignore'), strings))

def generate_yara_rule(file_path, strings, md5, sha256, description, author):
    rule_name = "malware_analysis_rule"
    date_str = datetime.now().strftime("%Y-%m-%d")

    yara_rule = f"""
rule {rule_name} {{
    meta:
        description = "{description}"
        author = "{author}"
        md5 = "{md5}"
        sha256 = "{sha256}"
        date = "{date_str}"
        type = "malware"

    strings:
"""
    for i, string in enumerate(strings):
        yara_rule += f'        $str{i} = "{string}"\n'

    yara_rule += """
    condition:
        all of them
}
"""
    return yara_rule

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 yarrules.py /path/to/malware.exe")
        sys.exit(1)

    file_path = sys.argv[1]

    description = input("Enter description: ")
    author = input("Enter author name: ")

    try:
        # Extract information
        md5, sha256 = compute_hashes(file_path)
        strings = extract_strings(file_path)
        yara_rule = generate_yara_rule(file_path, strings, md5, sha256, description, author)

        # Save to file
        with open("rules.yara", "w") as f:
            f.write(yara_rule)
        print("Yara rule generated and saved to rules.yara")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
