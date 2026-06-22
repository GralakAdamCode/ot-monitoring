#!/usr/bin/env python3
"""
Generate synthetic baseline traffic observations for ML model training.

This script populates the traffic_observations table with realistic "normal" 
traffic patterns based on each device's configuration. The ML model learns
from these observations during the warmup phase.

Usage:
    python generate_baseline.py [--count=120] [--hours=2] [--clear]

Args:
    --count: Number of observations per flow (default: 120)
    --hours: Generate observations spanning N hours (default: 2)
    --clear: Clear existing observations before generating (default: False)
"""

import os
import sys
import random
import argparse
from datetime import datetime, timedelta
from typing import Generator

import psycopg
from psycopg import sql


def get_connection():
    """Get PostgreSQL connection from environment."""
    db_url = os.getenv(
        "DATABASE_URL", 
        "postgresql+psycopg://otuser:otpass@localhost:5432/otmonitor"
    )
    # Remove sqlalchemy prefix if present
    db_url = db_url.replace("postgresql+psycopg://", "postgresql://")
    return psycopg.connect(db_url)


def generate_hmi_plc_observations(
    count: int, start_time: datetime
) -> Generator[dict, None, None]:
    """
    HMI → PLC control traffic (TCP:15000)
    Pattern: Polling every 3 seconds, 1-2 packets per window
    """
    for i in range(count):
        ts = start_time - timedelta(seconds=i)
        
        # Poll every 3 seconds
        if (i % 3) == 0:
            yield {
                "window_ts": ts,
                "src_ip": "172.28.0.20",
                "dst_ip": "172.28.0.10",
                "protocol": "tcp",
                "dst_port": 15000,
                "packet_count": 1,
                "packet_rate": 0.33,
                "byte_count": 82,
                "payload_bytes": 72,
                "avg_packet_size": 82.0,
                "avg_interarrival_ms": 1050.0 + random.gauss(0, 30),
                "jitter_ms": 45.5 + random.gauss(0, 5),
                "max_payload": 72,
                "arp_count": 0,
                "tcp_syn_count": 1,
                "tcp_rst_count": 0,
                "ml_anomaly": False,
                "ml_score": 0.015,
            }


def generate_sensor_observations(
    sensor_name: str,
    sensor_ip: str,
    port: int,
    count: int,
    start_time: datetime,
) -> Generator[dict, None, None]:
    """
    Sensor → PLC data (UDP)
    Pattern: Regular readings every second, consistent payload
    """
    base_iat = 985.0 + {"sensor1": 0, "sensor2": -10, "sensor3": 7}.get(sensor_name, 0)
    base_jitter = {"sensor1": 32, "sensor2": 28.5, "sensor3": 35.2}.get(sensor_name, 30)
    
    for i in range(count):
        ts = start_time - timedelta(seconds=i)
        
        yield {
            "window_ts": ts,
            "src_ip": sensor_ip,
            "dst_ip": "172.28.0.10",
            "protocol": "udp",
            "dst_port": port,
            "packet_count": 1,
            "packet_rate": 1.0,
            "byte_count": 96,
            "payload_bytes": 64,
            "avg_packet_size": 96.0,
            "avg_interarrival_ms": base_iat + random.gauss(0, 15),
            "jitter_ms": base_jitter + random.gauss(0, 3),
            "max_payload": 64,
            "arp_count": 0,
            "tcp_syn_count": 0,
            "tcp_rst_count": 0,
            "ml_anomaly": False,
            "ml_score": 0.010,
        }


def generate_arp_observations(
    count: int, start_time: datetime
) -> Generator[dict, None, None]:
    """
    PLC broadcast/ARP traffic
    Pattern: Occasional ARP requests, maintains network visibility
    """
    for i in range(count):
        ts = start_time - timedelta(seconds=i)
        
        # ARP every 5 seconds
        if (i % 5) == 0:
            yield {
                "window_ts": ts,
                "src_ip": "172.28.0.10",
                "dst_ip": "255.255.255.255",
                "protocol": "arp",
                "dst_port": None,
                "packet_count": 1,
                "packet_rate": 0.2,
                "byte_count": 42,
                "payload_bytes": 28,
                "avg_packet_size": 42.0,
                "avg_interarrival_ms": 4950.0 + random.gauss(0, 150),
                "jitter_ms": 150.0 + random.gauss(0, 20),
                "max_payload": 28,
                "arp_count": 1,
                "tcp_syn_count": 0,
                "tcp_rst_count": 0,
                "ml_anomaly": False,
                "ml_score": 0.012,
            }


def insert_observations(conn, observations: list[dict]) -> int:
    """Insert observations into database, return count inserted."""
    insert_sql = sql.SQL("""
        INSERT INTO traffic_observations (
            window_ts, src_ip, dst_ip, protocol, dst_port,
            packet_count, packet_rate, byte_count, payload_bytes,
            avg_packet_size, avg_interarrival_ms, jitter_ms,
            max_payload, arp_count, tcp_syn_count, tcp_rst_count,
            ml_anomaly, ml_score
        ) VALUES (
            %(window_ts)s, %(src_ip)s, %(dst_ip)s, %(protocol)s, %(dst_port)s,
            %(packet_count)s, %(packet_rate)s, %(byte_count)s, %(payload_bytes)s,
            %(avg_packet_size)s, %(avg_interarrival_ms)s, %(jitter_ms)s,
            %(max_payload)s, %(arp_count)s, %(tcp_syn_count)s, %(tcp_rst_count)s,
            %(ml_anomaly)s, %(ml_score)s
        )
    """)
    
    with conn.cursor() as cur:
        for obs in observations:
            # Round float values
            obs["avg_packet_size"] = round(obs["avg_packet_size"], 2)
            obs["avg_interarrival_ms"] = round(obs["avg_interarrival_ms"], 2)
            obs["jitter_ms"] = round(obs["jitter_ms"], 2)
            obs["packet_rate"] = round(obs["packet_rate"], 4)
            
            cur.execute(insert_sql, obs)
    
    conn.commit()
    return len(observations)


def clear_observations(conn):
    """Clear all traffic observations from database."""
    with conn.cursor() as cur:
        cur.execute("DELETE FROM traffic_observations")
    conn.commit()
    print("✓ Cleared existing traffic observations")


def main():
    parser = argparse.ArgumentParser(
        description="Generate baseline traffic observations for ML training"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=120,
        help="Number of observations per flow (default: 120)",
    )
    parser.add_argument(
        "--hours",
        type=float,
        default=2.0,
        help="Span observations over N hours (default: 2.0)",
    )
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear existing observations before generating",
    )
    
    args = parser.parse_args()
    
    try:
        conn = get_connection()
        print(f"✓ Connected to database")
        
        if args.clear:
            clear_observations(conn)
        
        start_time = datetime.utcnow() - timedelta(hours=args.hours)
        all_observations = []
        
        print(f"Generating {args.count} observations per flow...")
        
        # Generate observations for each flow
        flows = [
            ("HMI → PLC (TCP:15000)", generate_hmi_plc_observations(args.count, start_time)),
            ("Sensor1 → PLC (UDP:10001)", generate_sensor_observations(
                "sensor1", "172.28.0.31", 10001, args.count, start_time
            )),
            ("Sensor2 → PLC (UDP:10002)", generate_sensor_observations(
                "sensor2", "172.28.0.32", 10002, args.count, start_time
            )),
            ("Sensor3 → PLC (UDP:10003)", generate_sensor_observations(
                "sensor3", "172.28.0.33", 10003, args.count, start_time
            )),
            ("PLC ARP broadcast", generate_arp_observations(args.count, start_time)),
        ]
        
        for flow_name, gen in flows:
            flow_obs = list(gen)
            all_observations.extend(flow_obs)
            print(f"  ✓ {flow_name}: {len(flow_obs)} observations")
        
        print(f"\nInserting {len(all_observations)} total observations...")
        count = insert_observations(conn, all_observations)
        print(f"✓ Inserted {count} observations")
        
        # Print statistics
        with conn.cursor() as cur:
            cur.execute("""
                SELECT 
                    src_ip, dst_ip, protocol, dst_port,
                    COUNT(*) as count,
                    AVG(packet_rate) as avg_rate,
                    AVG(avg_interarrival_ms) as avg_iat_ms
                FROM traffic_observations
                GROUP BY src_ip, dst_ip, protocol, dst_port
                ORDER BY src_ip, dst_port
            """)
            
            print("\n📊 Flow Statistics:")
            print("-" * 90)
            for row in cur.fetchall():
                src_ip, dst_ip, protocol, dst_port, count, avg_rate, avg_iat = row
                port_str = f":{dst_port}" if dst_port else "(broadcast)"
                print(
                    f"  {src_ip:15} → {dst_ip:15} {protocol:3} {port_str:12} "
                    f"| {count:3} obs | rate: {avg_rate:.2f} p/s | IAT: {avg_iat:.0f}ms"
                )
        
        conn.close()
        print("\n✅ Baseline generation complete!")
        print(f"\nThe ML model will train on these patterns during the {args.hours:.1f}-hour warmup period.")
        return 0
        
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
