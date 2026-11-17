from .detection_engine import run_detections

def detect_dns_anomalies(records, config=None): return [a for a in run_detections(records, config) if a['detection_id'] in {'NET-004','NET-005'}]
