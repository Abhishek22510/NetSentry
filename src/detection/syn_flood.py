from .detection_engine import run_detections

def detect_syn_activity(records, config=None): return [a for a in run_detections(records, config) if a['detection_id']=='NET-002']
