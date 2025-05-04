#!/usr/bin/env python3
import os
import logging
from datetime import datetime

import pyshark
import pandas as pd
import numpy as np
from tqdm import tqdm
import argparse

# ─── CONFIGURATION ─────────────────────────────────────────────────────────────
LABEL          = 1
IDLE_THRESHOLD = 1.0   # seconds between packets to count as “idle”
BULK_MIN_PKTS  = 4     # minimum packets in a bulk burst
BULK_MIN_BYTES = 500   # minimum bytes in a bulk burst
# ────────────────────────────────────────────────────────────────────────────────

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")


def safe_stat(arr, func, default=0.0):
    try:
        return float(func(arr)) if arr else default
    except Exception:
        return default


def compute_active_idle(times, threshold):
    if len(times) < 2:
        return [], []
    deltas = np.diff(times)
    active, idle = [], []
    start = 0
    for i, dt in enumerate(deltas):
        if dt >= threshold:
            active.append(times[i] - times[start])
            idle.append(dt)
            start = i + 1
    active.append(times[-1] - times[start])
    return active, idle


def compute_bulk_metrics(times, lengths, min_pkts, min_bytes, threshold=IDLE_THRESHOLD):
    if len(times) < min_pkts:
        return {"avg_bytes": 0, "avg_packets": 0, "avg_rate": 0}
    bulks, deltas = [], np.diff(times)
    start = 0
    for i, dt in enumerate(deltas):
        if dt >= threshold:
            count = i - start + 1
            bsum = sum(lengths[start : i + 1])
            if count >= min_pkts and bsum >= min_bytes:
                dur = max(times[i] - times[start], 1e-4)
                bulks.append((count, bsum, bsum / dur))
            start = i + 1
    # final segment
    count = len(times) - start
    bsum = sum(lengths[start:])
    if count >= min_pkts and bsum >= min_bytes:
        dur = max(times[-1] - times[start], 1e-4)
        bulks.append((count, bsum, bsum / dur))

    if not bulks:
        return {"avg_bytes": 0, "avg_packets": 0, "avg_rate": 0}
    pkts = [b[0] for b in bulks]
    bts = [b[1] for b in bulks]
    rts = [b[2] for b in bulks]
    return {
        "avg_bytes": safe_stat(bts, np.mean),
        "avg_packets": safe_stat(pkts, np.mean),
        "avg_rate": safe_stat(rts, np.mean),
    }


def extract_features(pcap_file):
    if not os.path.isfile(pcap_file):
        logging.error(f"PCAP not found: {pcap_file}")
        return pd.DataFrame()

    cap = pyshark.FileCapture(
        pcap_file,
        display_filter="ip and tcp",
        use_json=True, include_raw=True,
        keep_packets=False
    )

    flows = {}
    logging.info("Grouping packets into flows…")
    for pkt in tqdm(cap, desc="Packets", unit="pkt"):
        try:
            ts = float(pkt.sniff_timestamp)
            tutc = datetime.utcfromtimestamp(ts)
            ip = pkt.ip
            sport = pkt.tcp.srcport
            dport = pkt.tcp.dstport

            base = (ip.src, sport, ip.dst, dport, "TCP")
            rev = (ip.dst, dport, ip.src, sport, "TCP")
            direction = "fwd"
            key = base
            if rev in flows:
                key, direction = rev, "bwd"

            if key not in flows:
                flows[key] = {
                    "start": tutc, "end": tutc,
                    "times": [], "lengths": [],
                    "fwd_times": [], "bwd_times": [],
                    "fwd_lengths": [], "bwd_lengths": [],
                    "fwd_hdrs": [], "bwd_hdrs": [],
                    "flags_hex": [],
                    "fwd_psh": 0, "bwd_psh": 0,
                    "fwd_urg": 0, "bwd_urg": 0,
                    "init_win_fwd": None, "init_win_bwd": None
                }
            f = flows[key]
            f["end"] = tutc

            length = int(pkt.length)
            f["times"].append(ts)
            f["lengths"].append(length)

            hdr = int(pkt.tcp.hdr_len) if hasattr(pkt.tcp, "hdr_len") else 0
            if direction == "fwd":
                f["fwd_times"].append(ts)
                f["fwd_lengths"].append(length)
                f["fwd_hdrs"].append(hdr)
                if f["init_win_fwd"] is None:
                    f["init_win_fwd"] = int(getattr(pkt.tcp, "window_size_value", 0))
            else:
                f["bwd_times"].append(ts)
                f["bwd_lengths"].append(length)
                f["bwd_hdrs"].append(hdr)
                if f["init_win_bwd"] is None:
                    f["init_win_bwd"] = int(getattr(pkt.tcp, "window_size_value", 0))

            flags = pkt.tcp.flags
            f["flags_hex"].append(flags)
            val = int(flags, 0)
            if direction == "fwd":
                f["fwd_psh"] += (val >> 3) & 1
                f["fwd_urg"] += (val >> 5) & 1
            else:
                f["bwd_psh"] += (val >> 3) & 1
                f["bwd_urg"] += (val >> 5) & 1

        except Exception:
            continue
    cap.close()

    logging.info("Building feature rows…")
    rows = []
    for f in tqdm(flows.values(), desc="Flows", unit="flow"):
        dur = max((f["end"] - f["start"]).total_seconds(), 1e-4)

        # overall flag counts
        cnts = dict(fin=0, syn=0, rst=0, psh=0, ack=0, urg=0, ece=0, cwr=0)
        for hx in f["flags_hex"]:
            try:
                v = int(hx, 0)
            except:
                continue
            cnts["fin"] += v & 1
            cnts["syn"] += (v >> 1) & 1
            cnts["rst"] += (v >> 2) & 1
            cnts["psh"] += (v >> 3) & 1
            cnts["ack"] += (v >> 4) & 1
            cnts["urg"] += (v >> 5) & 1
            cnts["ece"] += (v >> 6) & 1
            cnts["cwr"] += (v >> 7) & 1

        ts_sorted = sorted(f["times"])
        iats = np.diff(ts_sorted) if len(ts_sorted) > 1 else np.array([0.0])
        f_iats = np.diff(sorted(f["fwd_times"])) if len(f["fwd_times"]) > 1 else np.array([0.0])
        b_iats = np.diff(sorted(f["bwd_times"])) if len(f["bwd_times"]) > 1 else np.array([0.0])
        active, idle = compute_active_idle(ts_sorted, IDLE_THRESHOLD)
        bulk_f = compute_bulk_metrics(sorted(f["fwd_times"]), f["fwd_lengths"], BULK_MIN_PKTS, BULK_MIN_BYTES)
        bulk_b = compute_bulk_metrics(sorted(f["bwd_times"]), f["bwd_lengths"], BULK_MIN_PKTS, BULK_MIN_BYTES)

        tfp = len(f["fwd_lengths"])
        tbp = len(f["bwd_lengths"])
        tp = len(f["lengths"])
        tb = sum(f["lengths"])
        tfb = sum(f["fwd_lengths"])
        tbb = sum(f["bwd_lengths"])

        M = lambda a: safe_stat(a, np.mean)
        S = lambda a: safe_stat(a, np.std)
        X = lambda a: safe_stat(a, np.max)
        N = lambda a: safe_stat(a, np.min)
        V = lambda a: safe_stat(a, np.var)

        act_data = sum(1 for L in f["fwd_lengths"] if L > 0)

        rows.append({
            "flow duration":               dur,
            "total fwd packets":           tfp,
            "total backward packets":      tbp,
            "total length of fwd packets": tfb,
            "total length of bwd packets": tbb,
            "fwd packet length max":       X(f["fwd_lengths"]),
            "fwd packet length min":       N(f["fwd_lengths"]),
            "fwd packet length mean":      M(f["fwd_lengths"]),
            "fwd packet length std":       S(f["fwd_lengths"]),
            "bwd packet length max":       X(f["bwd_lengths"]),
            "bwd packet length min":       N(f["bwd_lengths"]),
            "bwd packet length mean":      M(f["bwd_lengths"]),
            "bwd packet length std":       S(f["bwd_lengths"]),
            "flow bytes/s":                tb / dur,
            "flow packets/s":              tp / dur,
            "flow iat mean":               M(iats),
            "flow iat std":                S(iats),
            "flow iat max":                X(iats),
            "flow iat min":                N(iats),
            "fwd iat total":               sum(f_iats),
            "fwd iat mean":                M(f_iats),
            "fwd iat std":                 S(f_iats),
            "fwd iat max":                 X(f_iats),
            "fwd iat min":                 N(f_iats),
            "bwd iat total":               sum(b_iats),
            "bwd iat mean":                M(b_iats),
            "bwd iat std":                 S(b_iats),
            "bwd iat max":                 X(b_iats),
            "bwd iat min":                 N(b_iats),
            "fwd psh flags":               f["fwd_psh"],
            "bwd psh flags":               f["bwd_psh"],
            "fwd urg flags":               f["fwd_urg"],
            "bwd urg flags":               f["bwd_urg"],
            "fwd header length":           M(f["fwd_hdrs"]),
            "bwd header length":           M(f["bwd_hdrs"]),
            "fwd packets/s":               tfp / dur,
            "bwd packets/s":               tbp / dur,
            "min packet length":           N(f["lengths"]),
            "max packet length":           X(f["lengths"]),
            "packet length mean":          M(f["lengths"]),
            "packet length std":           S(f["lengths"]),
            "packet length variance":      V(f["lengths"]),
            "fin flag count":              cnts["fin"],
            "syn flag count":              cnts["syn"],
            "rst flag count":              cnts["rst"],
            "psh flag count":              cnts["psh"],
            "ack flag count":              cnts["ack"],
            "urg flag count":              cnts["urg"],
            "cwe flag count":              cnts["cwr"],
            "ece flag count":              cnts["ece"],
            "down/up ratio":               (tbp / tfp if tfp > 0 else 0),
            "average packet size":         tb / max(tp, 1),
            "avg fwd segment size":        tfb / max(tfp, 1),
            "avg bwd segment size":        tbb / max(tbp, 1),
            "fwd header length.1":         S(f["fwd_hdrs"]),
            "fwd avg bytes/bulk":          bulk_f["avg_bytes"],
            "fwd avg packets/bulk":        bulk_f["avg_packets"],
            "fwd avg bulk rate":           bulk_f["avg_rate"],
            "bwd avg bytes/bulk":          bulk_b["avg_bytes"],
            "bwd avg packets/bulk":        bulk_b["avg_packets"],
            "bwd avg bulk rate":           bulk_b["avg_rate"],
            "subflow fwd packets":         tfp,
            "subflow fwd bytes":           tfb,
            "subflow bwd packets":         tbp,
            "subflow bwd bytes":           tbb,
            "init_win_bytes_forward":      f["init_win_fwd"] or 0,
            "init_win_bytes_backward":     f["init_win_bwd"] or 0,
            "act_data_pkt_fwd":            act_data,
            "min_seg_size_forward":        N(f["fwd_lengths"]),
            "active mean":                 M(active),
            "active std":                  S(active),
            "active max":                  X(active),
            "active min":                  N(active),
            "idle mean":                   M(idle),
            "idle std":                    S(idle),
            "idle max":                    X(idle),
            "idle min":                    N(idle),
            "attack":                      LABEL
        })

    return pd.DataFrame(rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract CIC-style attack features from a PCAP (attack=1)"
    )
    parser.add_argument("pcap",   help="Input PCAP file")
    parser.add_argument("output", help="Output CSV file")
    args = parser.parse_args()

    df = extract_features(args.pcap)
    df.to_csv(args.output, index=False)
    print(f"✅ Saved {len(df)} flows to {args.output}")