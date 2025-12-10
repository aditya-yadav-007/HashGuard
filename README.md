

# HashGuard – CLI Virus Scanner

![HashGuard](./img/icon.png)

**HashGuard** is a lightweight, drag-and-drop CLI virus scanner that uses **VirusTotal** to check files for malware. It hashes any file using SHA-256, queries VirusTotal, and gives a color-coded risk rating.

---

## 🛠 Tech Used

* **Python 3.x**
* **Requests** – for API requests
* **Hashlib** – for SHA-256 hashing
* **Colorama** – for colored CLI output
* **VirusTotal API** – for malware detection

---

## ✨ Features

* CLI-based drag-and-drop scanning
* SHA-256 hash computation of any file
* VirusTotal hash lookup
* Color-coded risk levels:

  * **High** → Red
  * **Medium** → Yellow
  * **None / Unknown** → Green
* Friendly message for unknown files: *“Very low chances of being a virus”*
* Handles no internet connection gracefully
* Pause at end to review results

> **Note:** This only runs on Windows

---

## ⚙️ Process

1. User drags a file onto the executable.
2. Program hashes the file using SHA-256.
3. Sends the hash to VirusTotal API.
4. Retrieves JSON scan results.
5. Prints a summary with color-coded risk level.
6. If file is unknown in VirusTotal, prints a “very low chances” message.

---

## 🧠 What I Learned

* How to interact with external APIs (VirusTotal) via Python.
* Handling JSON responses and extracting meaningful data.
* Using CLI color coding for better UX.
* Handling file operations and hashing securely.
* Error handling for network issues and invalid API keys.

---

## 🚀 How to Run

1. Clone the repository:

```bash
git clone https://github.com/<your-username>/HashGuard.git
cd HashGuard
```

2. Run the script:

```bash
Just Drop a File over it
```

3. When prompted, **enter your VirusTotal API Key** (must have your own key).

4. Drag and drop the file you want to scan onto the program.

5. Wait for the output. Press **Enter** to exit after the results are displayed.

---

## 🎬 Preview

![HashGuard Demo](./ss/Screenshot%202025-12-11%20030839.png)


---
