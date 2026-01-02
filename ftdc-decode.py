#!/usr/bin/env python3
"""
ftdc-decode.py
FTDC (Full-Time Diagnostic Data Capture) Decoder for MongoBleed Detection

Decodes MongoDB FTDC metrics files and extracts serverStatus.asserts time series
for spike detection in MongoBleed (CVE-2025-14847) analysis.

FTDC files are zlib-compressed streams of BSON documents with delta encoding.
This decoder extracts the asserts.user counter over time to identify exploitation bursts.

Usage:
    python3 ftdc-decode.py --dir ./collected-data/ftdc-files/
    python3 ftdc-decode.py --dir /var/lib/mongodb/diagnostic.data/

Output (JSON to stdout):
    [{"ts": "2025-01-02T10:00:00Z", "asserts_user": 150, "asserts_rollovers": 0}, ...]
"""

import argparse
import json
import os
import struct
import sys
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# FTDC document types
FTDC_TYPE_METADATA = 0
FTDC_TYPE_METRICS = 1

# Try to import bson from pymongo
try:
    import bson
    BSON_AVAILABLE = True
except ImportError:
    BSON_AVAILABLE = False


def decode_bson_document(data: bytes, offset: int = 0) -> tuple[dict, int]:
    """Decode a single BSON document from bytes.
    
    Returns (document, bytes_consumed).
    """
    if not BSON_AVAILABLE:
        raise RuntimeError("bson module not available")
    
    # BSON document starts with 4-byte little-endian length
    if len(data) < offset + 4:
        raise ValueError("Not enough data for BSON document")
    
    doc_len = struct.unpack_from('<i', data, offset)[0]
    if len(data) < offset + doc_len:
        raise ValueError(f"BSON document truncated: expected {doc_len}, got {len(data) - offset}")
    
    doc_bytes = data[offset:offset + doc_len]
    doc = bson.decode(doc_bytes)
    return doc, doc_len


def decode_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a variable-length integer (used in FTDC delta encoding).
    
    Returns (value, bytes_consumed).
    """
    result = 0
    shift = 0
    bytes_consumed = 0
    
    while offset + bytes_consumed < len(data):
        byte = data[offset + bytes_consumed]
        bytes_consumed += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
    
    # ZigZag decode for signed integers
    return (result >> 1) ^ -(result & 1), bytes_consumed


def flatten_document(doc: dict, prefix: str = '') -> dict:
    """Flatten a nested document into dot-notation keys."""
    result = {}
    for key, value in doc.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            result.update(flatten_document(value, full_key))
        else:
            result[full_key] = value
    return result


def extract_metrics_from_chunk(chunk_data: bytes) -> list[dict]:
    """Extract metrics samples from an FTDC metrics chunk.
    
    FTDC metrics chunks contain:
    1. Reference BSON document (full sample)
    2. Number of deltas (samples - 1)
    3. Delta-encoded values for each metric
    """
    if not BSON_AVAILABLE:
        return []
    
    samples = []
    offset = 0
    
    try:
        # Decode reference document
        ref_doc, doc_len = decode_bson_document(chunk_data, offset)
        offset += doc_len
        
        # Flatten reference document
        flat_ref = flatten_document(ref_doc)
        
        # Get numeric fields for delta decoding
        numeric_fields = []
        field_values = []
        for key, value in flat_ref.items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                numeric_fields.append(key)
                field_values.append(int(value) if isinstance(value, float) else value)
        
        # First sample is the reference
        samples.append(ref_doc.copy())
        
        if offset >= len(chunk_data):
            return samples
        
        # Read number of deltas
        num_deltas, consumed = decode_varint(chunk_data, offset)
        offset += consumed
        
        if num_deltas <= 0:
            return samples
        
        # Read deltas for each field
        # FTDC stores deltas column-wise: all deltas for field1, then all for field2, etc.
        all_deltas = []
        for _ in range(len(numeric_fields)):
            field_deltas = []
            for _ in range(num_deltas):
                if offset >= len(chunk_data):
                    break
                delta, consumed = decode_varint(chunk_data, offset)
                offset += consumed
                field_deltas.append(delta)
            all_deltas.append(field_deltas)
        
        # Reconstruct samples from deltas
        current_values = field_values.copy()
        for delta_idx in range(num_deltas):
            sample = ref_doc.copy()
            for field_idx, field_name in enumerate(numeric_fields):
                if delta_idx < len(all_deltas[field_idx]):
                    current_values[field_idx] += all_deltas[field_idx][delta_idx]
                # Update the sample with the new value
                parts = field_name.split('.')
                target = sample
                for part in parts[:-1]:
                    if part not in target:
                        target[part] = {}
                    target = target[part]
                target[parts[-1]] = current_values[field_idx]
            samples.append(sample)
        
    except Exception as e:
        # Log error but don't fail - return what we have
        print(f"Warning: Error extracting metrics: {e}", file=sys.stderr)
    
    return samples


def decode_ftdc_file(filepath: Path) -> list[dict]:
    """Decode an FTDC file and extract all samples.
    
    FTDC files contain:
    - Metadata chunks (type 0): server info, etc.
    - Metrics chunks (type 1): compressed time series data
    - Schema chunks (type 2): reference document structure
    
    Type 1 data format:
    - First 4 bytes: uncompressed size (little-endian uint32)
    - Rest: zlib-compressed data containing:
      - Reference BSON document (full serverStatus snapshot)
      - Delta-encoded subsequent samples
    """
    if not BSON_AVAILABLE:
        return []
    
    samples = []
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except (IOError, OSError) as e:
        print(f"Warning: Cannot read {filepath}: {e}", file=sys.stderr)
        return []
    
    offset = 0
    while offset < len(data):
        try:
            if len(data) < offset + 4:
                break
            
            chunk_len = struct.unpack_from('<i', data, offset)[0]
            if chunk_len <= 0 or offset + chunk_len > len(data):
                break
            
            chunk_bytes = data[offset:offset + chunk_len]
            chunk = bson.decode(chunk_bytes)
            offset += chunk_len
            
            chunk_type = chunk.get('type', -1)
            chunk_data = chunk.get('data', b'')
            
            if chunk_type == FTDC_TYPE_METRICS and chunk_data and len(chunk_data) > 4:
                # First 4 bytes are the uncompressed size, then zlib data
                try:
                    zlib_data = chunk_data[4:]
                    decompressed = zlib.decompress(zlib_data)
                    chunk_samples = extract_metrics_from_chunk(decompressed)
                    samples.extend(chunk_samples)
                except zlib.error as e:
                    print(f"Warning: zlib decompression failed: {e}", file=sys.stderr)
                    continue
            
        except Exception as e:
            print(f"Warning: Error decoding chunk at offset {offset}: {e}", file=sys.stderr)
            offset += 1
    
    return samples


def extract_asserts_timeseries(samples: list[dict]) -> list[dict]:
    """Extract timestamp and asserts.user from samples."""
    timeseries = []
    
    for sample in samples:
        # Try to find timestamp
        ts = None
        if 'start' in sample:
            ts = sample['start']
        elif 'localTime' in sample:
            ts = sample['localTime']
        elif 'serverStatus' in sample and 'localTime' in sample.get('serverStatus', {}):
            ts = sample['serverStatus']['localTime']
        
        # Try to find asserts
        asserts = None
        if 'serverStatus' in sample and 'asserts' in sample.get('serverStatus', {}):
            asserts = sample['serverStatus']['asserts']
        elif 'asserts' in sample:
            asserts = sample['asserts']
        
        if ts is not None and asserts is not None:
            # Format timestamp
            if isinstance(ts, datetime):
                ts_str = ts.strftime('%Y-%m-%dT%H:%M:%SZ')
            else:
                ts_str = str(ts)
            
            entry = {
                'ts': ts_str,
                'asserts_user': asserts.get('user', 0),
                'asserts_rollovers': asserts.get('rollovers', 0),
            }
            
            # Include other assert types if present
            for key in ['regular', 'warning', 'msg', 'tripwire']:
                if key in asserts:
                    entry[f'asserts_{key}'] = asserts[key]
            
            timeseries.append(entry)
    
    return timeseries


def try_external_decoder(ftdc_dir: Path) -> Optional[list[dict]]:
    """Try to use external FTDC decoding tools as fallback.
    
    Tries:
    1. ftdc-utils (Go tool)
    2. mongodump --diagnostic (if available)
    """
    import shutil
    import subprocess
    
    # Try ftdc-utils
    ftdc_utils = shutil.which('ftdc-utils')
    if ftdc_utils:
        try:
            result = subprocess.run(
                [ftdc_utils, 'decode', '--dir', str(ftdc_dir), '--format', 'json'],
                capture_output=True,
                text=True,
                timeout=300
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                return extract_asserts_timeseries(data)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
            print(f"Warning: ftdc-utils failed: {e}", file=sys.stderr)
    
    return None


def decode_ftdc_directory(ftdc_dir: Path) -> list[dict]:
    """Decode all FTDC files in a directory."""
    if not BSON_AVAILABLE:
        print("Warning: pymongo/bson not available, trying external tools...", file=sys.stderr)
        result = try_external_decoder(ftdc_dir)
        if result is not None:
            return result
        print("Error: No FTDC decoder available. Install pymongo: pip install pymongo", file=sys.stderr)
        return []
    
    all_samples = []
    
    # Find metrics files
    metrics_files = sorted(ftdc_dir.glob('metrics.*'))
    
    if not metrics_files:
        print(f"Warning: No metrics.* files found in {ftdc_dir}", file=sys.stderr)
        return []
    
    for filepath in metrics_files:
        print(f"Decoding {filepath.name}...", file=sys.stderr)
        samples = decode_ftdc_file(filepath)
        all_samples.extend(samples)
    
    # Extract asserts timeseries
    timeseries = extract_asserts_timeseries(all_samples)
    
    # Sort by timestamp
    timeseries.sort(key=lambda x: x['ts'])
    
    # Remove duplicates (same timestamp)
    seen = set()
    unique = []
    for entry in timeseries:
        if entry['ts'] not in seen:
            seen.add(entry['ts'])
            unique.append(entry)
    
    return unique


def detect_spikes(timeseries: list[dict], threshold: int = 100) -> list[dict]:
    """Detect spikes in asserts.user values.
    
    Returns list of spike windows with start/end times and delta.
    """
    spikes = []
    
    for i in range(1, len(timeseries)):
        prev = timeseries[i - 1]
        curr = timeseries[i]
        
        delta = curr['asserts_user'] - prev['asserts_user']
        
        if delta >= threshold:
            spikes.append({
                'start_ts': prev['ts'],
                'end_ts': curr['ts'],
                'delta_user': delta,
                'prev_user': prev['asserts_user'],
                'curr_user': curr['asserts_user'],
            })
    
    return spikes


def main():
    parser = argparse.ArgumentParser(
        description='Decode MongoDB FTDC files and extract asserts time series',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
    # Decode FTDC files and output time series
    python3 ftdc-decode.py --dir ./collected-data/ftdc-files/

    # Detect spikes with custom threshold
    python3 ftdc-decode.py --dir /var/lib/mongodb/diagnostic.data/ --detect-spikes --threshold 50

    # Output raw samples (verbose)
    python3 ftdc-decode.py --dir ./ftdc-files/ --raw
        '''
    )
    
    parser.add_argument(
        '--dir', '-d',
        type=Path,
        required=True,
        help='Directory containing FTDC metrics.* files'
    )
    
    parser.add_argument(
        '--detect-spikes', '-s',
        action='store_true',
        help='Detect spikes in asserts.user and output spike windows'
    )
    
    parser.add_argument(
        '--threshold', '-t',
        type=int,
        default=100,
        help='Spike detection threshold for asserts.user delta (default: 100)'
    )
    
    parser.add_argument(
        '--raw', '-r',
        action='store_true',
        help='Output raw samples instead of asserts time series'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress progress messages'
    )
    
    args = parser.parse_args()
    
    if not args.dir.exists():
        print(f"Error: Directory not found: {args.dir}", file=sys.stderr)
        sys.exit(1)
    
    if not args.dir.is_dir():
        print(f"Error: Not a directory: {args.dir}", file=sys.stderr)
        sys.exit(1)
    
    # Suppress progress messages if quiet
    if args.quiet:
        class DevNull:
            def write(self, msg): pass
            def flush(self): pass
        sys.stderr = DevNull()
    
    # Decode FTDC files
    timeseries = decode_ftdc_directory(args.dir)
    
    if not timeseries:
        print("[]")
        sys.exit(0)
    
    if args.detect_spikes:
        # Output spike detection results
        spikes = detect_spikes(timeseries, args.threshold)
        output = {
            'total_samples': len(timeseries),
            'time_range': {
                'start': timeseries[0]['ts'],
                'end': timeseries[-1]['ts'],
            },
            'spikes': spikes,
            'spike_count': len(spikes),
        }
        print(json.dumps(output, indent=2))
    else:
        # Output time series
        print(json.dumps(timeseries, indent=2))


if __name__ == '__main__':
    main()

