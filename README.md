# Revealer
Detect disguised malware via magic number file analysis.

## Installation
```bash
git clone https://github.com/femi49/revealer.git
cd revealer
chmod +x revealer
```

## Usage
```bash
./revealer -f <file or directory>
./revealer -f suspicious.jpg
./revealer -f /downloads/ --no-recurse
./revealer -f malware_sample.png --json
```

## Author
Femi Awoyomi