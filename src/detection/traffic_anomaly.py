from .detection_engine import run_detections

def detect_traffic_anomalies(records, config=None): return [a for a in run_detections(records, config) if a['detection_id'] in {'NET-003','NET-006','NET-007','NET-008'}]
