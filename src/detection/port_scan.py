from .detection_engine import run_detections

def detect_port_scans(records, config=None): return [a for a in run_detections(records, config) if a['detection_id']=='NET-001']
