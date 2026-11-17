from pathlib import Path

def validate_capture_path(path, max_size_mb=250):
    p=Path(path)
    if not p.is_file(): return False, 'Capture file does not exist.'
    if p.suffix.lower() not in {'.pcap','.pcapng','.cap'}: return False, 'Only PCAP and PCAPNG files are supported.'
    if p.stat().st_size > max_size_mb*1024*1024: return False, f'Capture exceeds the {max_size_mb} MB limit.'
    return True, ''
