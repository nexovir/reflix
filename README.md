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
   git clone https://github.com/yourusername/reflix.git
   cd reflix
   ./install.sh
   pip install -r requirementes.txt
```

## Usage

```python reflix.py -l <urls_file> [options]


## Example

```python reflix.py -l test1.txt -w wordlist.txt -X GET,POST -H "header2: value2" -H "header1: value1" -p nexovir -o t.txt -po 
params.txt 
-c 15 -p nexovir -d -he

## Contact

```Developed by Nexovir
Twitter: @nexovir
GitHub: https://github.com/nexovir
