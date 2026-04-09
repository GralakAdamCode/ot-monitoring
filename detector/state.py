import threading
import time
from collections import defaultdict, deque

from config import CONFIG
from models import WindowStats


START_TS = time.time()
LOCK = threading.Lock()

CURRENT_WINDOWS = defaultdict(WindowStats)

LAST_PACKET_TS_BY_FLOW: dict[tuple, float] = {}
RECENT_IATS_BY_FLOW: dict[tuple, deque] = defaultdict(
    lambda: deque(maxlen=CONFIG.recent_iat_window)
)

LAST_SEEN_BY_IP: dict[str, float] = {}
EXPECTED_IPS: set[str] = set()
SILENT_IPS: set[str] = set()

KNOWN_IP_TO_MAC: dict[str, str] = {}
KNOWN_PEERS: dict[str, set[str]] = defaultdict(set)
KNOWN_ROUTES: dict[str, set[tuple]] = defaultdict(set)

BASELINES = defaultdict(
    lambda: {
        "samples": 0,
        "packet_rate": 0.0,
        "avg_packet_size": 0.0,
        "avg_interarrival_ms": 0.0,
        "jitter_ms": 0.0,
        "response_latency_ms": 0.0,
    }
)

RECENT_EVENT_CACHE: dict[tuple, float] = {}
TRAINING_VECTORS = deque(maxlen=5000)
IF_MODEL = None

PENDING_TCP_REQUESTS: dict[tuple, deque] = defaultdict(deque)