import hashlib
import requests
import sys
import os
from colorama import init, Fore, Style
init(autoreset=True)  # Automatically resets colors after each print


# ---------------------------
# Colors (for CLI rating)
# ---------------------------
class Color:
    RED = Fore.RED
    YELLOW = Fore.YELLOW
    GREEN = Fore.GREEN
    RESET = Style.RESET_ALL



# ---------------------------
# Internet Check
# ---------------------------
def check_internet():
    try:
        requests.get("https://www.google.com", timeout=3)
        return True
    except:
        return False


# ---------------------------
# SHA-256 Hash Function
# ---------------------------
def sha256_file(path):
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


# ---------------------------
# VirusTotal Hash Lookup
# ---------------------------
def vt_lookup(hash_value, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": api_key}

    session = requests.Session()
    session.headers.update(headers)

    try:
        response = session.get(url)
    except requests.exceptions.RequestException:
        print("Error: Failed to connect to VirusTotal.")
        return None

    if response.status_code == 401:
        print(Color.RED + "Error: Invalid API Key!" + Color.RESET)
        return None

    if response.status_code == 404:
        print("File not found in VirusTotal dataset.")
        print(Color.GREEN + "Very low chances of being a virus." + Color.RESET)
        return None

    if response.status_code != 200:
        print(f"VirusTotal Error: {response.status_code} {response.text}")
        return None

    return response.json()


# ---------------------------
# Rating System
# ---------------------------
def get_rating(vt_json):
    stats = vt_json["data"]["attributes"]["last_analysis_stats"]
    malicious = stats["malicious"]
    suspicious = stats["suspicious"]

    if malicious >= 3:
        return "HIGH", Color.RED
    if malicious > 0 or suspicious > 0:
        return "MEDIUM", Color.YELLOW
    return "NONE", Color.GREEN


# ---------------------------
# Pretty Print Summary
# ---------------------------
def show_summary(vt_json):
    data = vt_json["data"]["attributes"]
    stats = data["last_analysis_stats"]

    rating, color = get_rating(vt_json)

    print("\n====== VirusTotal Report ======")
    print(f"Malicious : {stats['malicious']}")
    print(f"Suspicious: {stats['suspicious']}")
    print(f"Undetected: {stats['undetected']}")
    print(f"Harmless  : {stats['harmless']}")

    print("\nOverall Rating:", color + rating + Color.RESET)

    print("\n--- Engines Flagged ---")
    for engine, result in data["last_analysis_results"].items():
        if result["category"] in ("malicious", "suspicious"):
            print(f"{engine}: {result['result']}")


# ---------------------------
# Main
# ---------------------------
def main():
    print("===== VTCheck Antivirus CLI v0 =====")
    
    api_key = input("Enter your VirusTotal API Key: ").strip()
    if not api_key:
        print("No API Key provided.")
        input("\nPress Enter to exit...")
        sys.exit(1)

    if len(sys.argv) != 2:
        print("Drag and drop a file over this EXE to scan it. Do not run directly.")
        input("\nPress Enter to exit...")  # Wait for user
        sys.exit(0)


    filepath = sys.argv[1]

    if not os.path.isfile(filepath):
        print("Invalid File")
        input("\nPress Enter to exit...")
        sys.exit(1)

    if not check_internet():
        print("Internet Error – No connection.")
        input("\nPress Enter to exit...")
        sys.exit(1)

    print(f"[*] Hashing: {filepath}")
    file_hash = sha256_file(filepath)
    print(f"[+] SHA256: {file_hash}")

    print("\n[*] Sending hash to VirusTotal...")
    vt_data = vt_lookup(file_hash, api_key)

    if vt_data:
        show_summary(vt_data)
    input("\nPress Enter to exit...")



if __name__ == "__main__":
    main()
