# Reflix

A smart parameter injection and fuzzing tool designed for web vulnerability discovery and scanning.

---

## Features

- Automated parameter discovery and fuzzing with multi-thread support
- Supports HTTP GET and POST methods
- Custom headers and proxy support
- Integration with powerful external tools: **Nuclei**, **Fallparams**, and **Injector**
- Configurable rate limiting and delays
- Output results in plain text or JSON format
- Notifications via Telegram
- Easy-to-use CLI with helpful flags and debugging mode

---

## Credits

Reflix leverages the outstanding work of the following projects and authors:

- [Nuclei](https://github.com/projectdiscovery/nuclei) — by ProjectDiscovery
- [Fallparams](https://github.com/ImAyrix/fallparams) — by ImAyrix
- [Injector](https://github.com/nexovir/injector) — by Nexovir

Thanks to these tools, Reflix combines parameter discovery, injection, and vulnerability scanning into one streamlined workflow.

---

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/nexovir/reflix.git
   cd reflix
   ```

2. **Run the install script:**

   ```bash
   ./install.sh
   ```

3. **Install Python dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

Run Reflix with:

```bash
python reflix.py -l <urls_file> [options]
```

### Common options:

| Flag   | Description                                                | Default          |
| ------ | ---------------------------------------------------------- | ---------------- |
| `-l`   | Path to file containing list of target URLs (required)     |                  |
| `-p`   | Comma-separated parameter to test for reflection           | `nexovir`        |
| `-w`   | Path to a file containing parameters to fuzz               |                  |
| `-X`   | HTTP methods to use (e.g., GET,POST)                       | `GET,POST`       |
| `-H`   | Custom headers (can specify multiple times)                |                  |
| `-x`   | HTTP proxy to use (e.g., http://127.0.0.1:8080)            |                  |
| `-c`   | Number of URLs to process per batch                        | `25`             |
| `-he`  | Enable heavy fuzzing (re-fuzzes all discovered parameters) | `False`          |
| `-t`   | Number of concurrent threads                               | `1`              |
| `-rd`  | Delay (in seconds) between requests                        | `0`              |
| `-n`   | Enable notifications                                       | `False`          |
| `-log` | Logger file path                                           | `logger.txt`     |
| `-s`   | Silent mode (disable CLI prints)                           | `False`          |
| `-d`   | Enable debug mode                                          | `False`          |
| `-o`   | Output file to write found issues/vulnerabilities          |                  |
| `-po`  | Path to save discovered parameters                         | `all_params.txt` |
| `-jo`  | Export results in JSON format                              |                  |

---

## Example

```bash
python reflix.py -l test1.txt -w wordlist.txt -X GET,POST -H "User-Agent: Mozilla/5.0" -H "Authorization: Bearer token" -p nexovir -o
results.txt -po params.txt -c 15 -d -he
```

---

## Contact

Developed by Nexovir  
Twitter: [@nexovir](https://twitter.com/nexovir)  
GitHub: [https://github.com/nexovir](https://github.com/nexovir)
