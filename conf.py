
"""
File Type Identification Tool
Detects real filetype via magic numbers.

"""

import json
from pathlib import Path 
import time

from magicdb import MAGIC_DATABASE

"""This code reads the first 32 bytes"""
def read_header(filepath, num_bytes=32):
    with open(filepath, 'rb') as f:
        return f.read(num_bytes)


"""This code matches header bytes agaisnt the signature db"""
def idreal_type(header_bytes):
    for mgc, (description, expected_results) in MAGIC_DATABASE.items():
        if header_bytes.startswith(mgc):
            return description, expected_results


    if header_bytes[:4] == b'RIFF' and header_bytes[8:12] == b'WEBP':
        return 'WebP image', ['webP']
    

    return 'Unknown / Unrecognized format', []


def file_check(filepath):
    path = Path(filepath)
    declared_ext= path.suffix.lstrip('.').lower()

    header =read_header(filepath)
    real_type, valid_exts = idreal_type(header)

    mismatch = declared_ext not in valid_exts if valid_exts else False

    HIGH_RISK_TYPES = ['Windows PE executable', 'Linux ELF executable', 'Mach-O fat binary (macOS)']

    risk_level = 'high' if (mismatch and real_type in HIGH_RISK_TYPES) else \
             'medium' if mismatch else \
             'clean'

    return{
        'file': str(path),
        'declared_extension': declared_ext,
        'real_type':real_type,
        'mismatch': mismatch,
        'risk_level': 'risk_level',
        'header_hex': header[:16].hex(' ') # first 16 bytes for debugging
    }

def scan_directory(directory, recursive=True):
    results= []
    path = Path(directory)

    glob_pattern = '**/*' if recursive else '*'

    scan_start = time.perf_counter() #Start total scan timer
    for file_path in path.glob(glob_pattern):
        if file_path.is_file():
            file_start = time.perf_counter() #Start per-file timer
            try:
                result = file_check(file_path)
                result['scan_time_ms'] = round((time.perf_counter()-file_start) * 1000, 3)
                results.append(result)
            except (PermissionError, OSError) as e:
                results.append({
                    'file': str(file_path),
                    'error': str(e),
                    'scan_time_ms': round((time.perf_counter() - file_start) * 1000, 3)
                })

    total_elapsed = time.perf_counter() - scan_start # End total scan timer    
    return results, total_elapsed

def print_report(results, total_elapsed):
    flagged = [r for r in results if r.get('mismatch')]
    clean = [r for r in results if not r.get('mismatch') and 'error' not in r]
    errors = [r for r in results if 'error' in r]

    # Format total time intelligently
    if total_elapsed < 1:
        time_display = f"{total_elapsed * 1000:.1f}ms"
    else:
        time_display = f"{total_elapsed:.2f}s" 

    #Calculate average per file time
    timed = [r for r in results if 'scan_time_ms' in r]
    avg_ms = sum(r['scan_time_ms'] for r in timed) / len(timed) if timed else 0

    print(f"\n{'='*60}")
    print(f"   SCAN RESULTS: {len(results)} files scanned")
    print(f"   Total Scan time      : {time_display}")
    print(f"   Avg time per file    : {avg_ms:.3f}ms")
    print(f"   Flagged mismatches   : {len(flagged)}")
    print(f"   Clean                : {len(clean)}")
    print(f"   Errors               : {len(errors)} ")
    print(f"{'='*60}\n")  

    if flagged:
        print("[!] FLAGGED FILES:")
        for r in flagged:
            print(f"    {r['file']}")
            print(f"    Declared  :  .{r['declared_extension']}")
            print(f"    Real type :   {r['real_type']}")
            print(f"    Header    :   {r['header_hex']}")
            print(f"    Scan time :   {r['scan_time_ms']}ms\n ")