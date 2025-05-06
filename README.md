# SSRFly

A high-speed, low false-positive SSRF vulnerability testing tool with both command-line and web interfaces.

## Features

- **High-Speed Performance**: Multi-threaded architecture for lightning-fast scanning
- **Low False Positives**: Advanced validation techniques to minimize false positives
- **Comprehensive Payloads**: Tests against numerous SSRF vectors and bypass techniques
- **Easy to Use**: Simple command line interface and web UI
- **Detailed Reporting**: Clear, actionable vulnerability reports

## Installation

1. Clone the repository:
```
git clone https://github.com/yourusername/ssrfly.git
cd ssrfly
```

2. Install the required dependencies:
```
pip install -r dependencies.txt
```

## Usage

### Command Line Interface

To scan a single URL:
```
python ssrfly.py -u https://example.com
```

To scan multiple URLs from a file:
```
python ssrfly.py -f targets.txt
```

Additional options:
```
python ssrfly.py -h

Options:
  -h, --help            show this help message and exit
  -u URL, --url URL     Single URL to test for SSRF vulnerabilities
  -f FILE, --file FILE  File containing URLs to test (one per line)
  -t THREADS, --threads THREADS
                        Number of threads to use (default: 10)
  -o OUTPUT, --output OUTPUT
                        File to save results
  -v, --verbose         Enable verbose output
  --timeout TIMEOUT     Request timeout in seconds (default: 10)
```

### Web Interface

To start the web interface:
```
python main.py
```

Then open your browser and navigate to:
```
http://localhost:5000
```

## Dependencies

- Flask
- Requests
- Colorama
- Gunicorn (for production deployment)

## Created By

aryahmpillai