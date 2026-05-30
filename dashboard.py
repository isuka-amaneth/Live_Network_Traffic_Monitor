import time
import socket
import subprocess
import json
import ipaddress
from urllib import request as urlrequest
import streamlit as st
import pandas as pd
import psutil
import joblib
import plotly.graph_objects as go
from scapy.all import sniff, IP, TCP, UDP

st.set_page_config(page_title="Live Network Monitor", layout="wide")

SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 161: "SNMP", 443: "HTTPS", 465: "SMTPS",
    587: "SMTP", 993: "IMAPS", 995: "POP3S", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-alt", 8443: "HTTPS-alt",
}
NSL_SERVICE = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain_u",
               80: "http", 110: "pop_3", 143: "imap4", 443: "http", 3306: "sql_net"}
PLAINTEXT = {21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3", 143: "IMAP"}

PORTSCAN_PORTS, FLOOD_PACKETS, FANOUT_DESTS, DNS_VOLUME = 15, 200, 50, 100
SEVERITY = {"Port scan": "high", "Flood": "high", "High fan-out": "high",
            "Unencrypted traffic": "medium", "DNS volume": "medium"}


@st.cache_resource
def load_live_model():
    try:
        return joblib.load("live_model.joblib")
    except Exception:
        return None


def service_name(port):
    return "-" if port is None else SERVICES.get(int(port), str(int(port)))


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close(); return ip
    except Exception:
        return "unknown"


def get_wifi_ssid():
    try:
        out = subprocess.check_output(["netsh", "wlan", "show", "interfaces"],
                                      text=True, stderr=subprocess.DEVNULL, timeout=4)
        for line in out.splitlines():
            t = line.strip()
            if t.lower().startswith("ssid") and not t.lower().startswith("bssid"):
                return t.split(":", 1)[1].strip() or "not connected"
    except Exception:
        pass
    return "n/a (wired or unavailable)"


def get_active_interface():
    try:
        local = get_local_ip(); stats = psutil.net_if_stats()
        for name, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET and a.address == local:
                    s = stats.get(name)
                    return name, (f"{s.speed} Mbps" if s and s.speed else "unknown")
    except Exception:
        pass
    return "unknown", "unknown"


def measure_throughput(seconds=1.0):
    c1 = psutil.net_io_counters(); time.sleep(seconds); c2 = psutil.net_io_counters()
    return (round((c2.bytes_recv - c1.bytes_recv)/seconds/1024, 1),
            round((c2.bytes_sent - c1.bytes_sent)/seconds/1024, 1))


def speed_gauge(label, value, max_val):
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=value,
        number={"suffix": " KB/s"}, title={"text": label},
        gauge={"axis": {"range": [0, max_val]}, "bar": {"color": "#4c8bf5"},
               "steps": [{"range": [0, max_val * 0.5], "color": "#16202e"},
                         {"range": [max_val * 0.5, max_val * 0.8], "color": "#22303f"}]}))
    fig.update_layout(height=240, margin=dict(l=20, r=20, t=60, b=20),
                      paper_bgcolor="rgba(0,0,0,0)", font={"color": "#ddd"})
    return fig


def is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except Exception:
        return False


def geolocate(ips):
    """Look up country/city/coords for PUBLIC IPs via ip-api.com. Local IPs never leave your machine."""
    if "geo_cache" not in st.session_state:
        st.session_state["geo_cache"] = {}
    cache = st.session_state["geo_cache"]
    todo = [ip for ip in ips if ip not in cache]
    public_todo = [ip for ip in todo if is_public(ip)]
    for ip in todo:
        if ip not in public_todo:
            cache[ip] = {"country": "Local network", "city": "", "lat": None, "lon": None}
    for i in range(0, len(public_todo), 100):
        chunk = public_todo[i:i + 100]
        try:
            payload = json.dumps([{"query": ip, "fields": "query,status,country,city,lat,lon"}
                                  for ip in chunk]).encode()
            req = urlrequest.Request("http://ip-api.com/batch", data=payload,
                                     headers={"Content-Type": "application/json"})
            with urlrequest.urlopen(req, timeout=6) as resp:
                results = json.loads(resp.read().decode())
            for r in results:
                if r.get("status") == "success":
                    cache[r["query"]] = {"country": r.get("country", "?"), "city": r.get("city", ""),
                                         "lat": r.get("lat"), "lon": r.get("lon")}
                else:
                    cache[r["query"]] = {"country": "Unknown", "city": "", "lat": None, "lon": None}
        except Exception:
            for ip in chunk:
                cache.setdefault(ip, {"country": "Lookup failed", "city": "", "lat": None, "lon": None})
    return {ip: cache.get(ip, {"country": "?", "city": "", "lat": None, "lon": None}) for ip in ips}

def get_my_location():
    """Geolocate your own public IP once, so we can draw lines from 'you' to destinations."""
    if "my_loc" not in st.session_state:
        try:
            with urlrequest.urlopen("http://ip-api.com/json/?fields=status,country,city,lat,lon",
                                    timeout=6) as resp:
                r = json.loads(resp.read().decode())
            if r.get("status") == "success" and r.get("lat") is not None:
                st.session_state["my_loc"] = {"lat": r["lat"], "lon": r["lon"],
                                              "city": r.get("city", ""), "country": r.get("country", "")}
            else:
                st.session_state["my_loc"] = None
        except Exception:
            st.session_state["my_loc"] = None
    return st.session_state["my_loc"]


def traffic_map(my_loc, dests):
    """World map with lines from your location to each destination."""
    line_lat, line_lon = [], []
    for d in dests:
        line_lat += [my_loc["lat"], d["lat"], None]
        line_lon += [my_loc["lon"], d["lon"], None]
    fig = go.Figure()
    fig.add_trace(go.Scattergeo(lat=line_lat, lon=line_lon, mode="lines",
                                line=dict(width=1, color="#4c8bf5"), opacity=0.6,
                                hoverinfo="skip", showlegend=False))
    fig.add_trace(go.Scattergeo(lat=[d["lat"] for d in dests], lon=[d["lon"] for d in dests],
                                mode="markers", marker=dict(size=6, color="#e05260"),
                                text=[d["label"] for d in dests], hoverinfo="text", name="Destinations"))
    fig.add_trace(go.Scattergeo(lat=[my_loc["lat"]], lon=[my_loc["lon"]], mode="markers",
                                marker=dict(size=12, color="#41d18f"),
                                text=["You"], hoverinfo="text", name="You"))
    fig.update_layout(height=430, margin=dict(l=0, r=0, t=10, b=0),
                      paper_bgcolor="rgba(0,0,0,0)", showlegend=True,
                      geo=dict(projection_type="natural earth", showland=True,
                               landcolor="#1b2430", showocean=True, oceancolor="#0e1117",
                               lakecolor="#0e1117", bgcolor="rgba(0,0,0,0)",
                               countrycolor="#33414f", coastlinecolor="#33414f"))
    return fig

def capture(duration):
    packets = sniff(timeout=duration, store=True)
    rows = []
    for pkt in packets:
        if IP in pkt:
            proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "other"
            dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None)
            rows.append({"source": pkt[IP].src, "destination": pkt[IP].dst,
                         "protocol": proto, "dst_port": dport, "size": len(pkt)})
    return pd.DataFrame(rows)


def simulated_capture():
    """Clearly-labelled SIMULATED attack traffic for safe demos. Scans no real device."""
    rows = []
    attacker, target = "10.0.0.5", "10.0.0.20"
    for port in range(20, 45):
        rows.append({"source": attacker, "destination": target,
                     "protocol": "TCP", "dst_port": port, "size": 60})
    for _ in range(250):
        rows.append({"source": attacker, "destination": "10.0.0.30",
                     "protocol": "UDP", "dst_port": 53, "size": 80})
    for _ in range(10):
        rows.append({"source": attacker, "destination": "142.250.1.1",
                     "protocol": "TCP", "dst_port": 443, "size": 800})
    return pd.DataFrame(rows)


def to_features(df):
    host_counts = df["destination"].value_counts().to_dict()
    rows, keys = [], []
    for (src, dst), g in df.groupby(["source", "destination"]):
        proto = str(g["protocol"].iloc[0]).lower()
        ports = g["dst_port"].dropna()
        port = int(ports.iloc[0]) if len(ports) else 0
        rows.append({
            "protocol_type": proto if proto in ("tcp", "udp", "icmp") else "tcp",
            "service": NSL_SERVICE.get(port, "other"),
            "src_bytes": int(g["size"].sum()), "dst_bytes": 0, "duration": 0,
            "count": len(g), "dst_host_count": int(host_counts.get(dst, 1)),
        })
        keys.append((src, dst))
    return pd.DataFrame(rows), keys


def detect(df, duration):
    alerts = []
    tcp = df[df["protocol"] == "TCP"]
    for (src, dst), grp in tcp.groupby(["source", "destination"]):
        if grp["dst_port"].nunique() >= PORTSCAN_PORTS:
            alerts.append(("Port scan", f"{src} probed {grp['dst_port'].nunique()} ports on {dst}"))
    for dst, cnt in df["destination"].value_counts().items():
        if cnt >= FLOOD_PACKETS:
            alerts.append(("Flood", f"{cnt} packets sent to {dst} in {duration}s"))
    for src, grp in df.groupby("source"):
        if grp["destination"].nunique() >= FANOUT_DESTS:
            alerts.append(("High fan-out", f"{src} contacted {grp['destination'].nunique()} destinations"))
    plain = sorted({PLAINTEXT[int(p)] for p in df["dst_port"].dropna().unique() if int(p) in PLAINTEXT})
    if plain:
        alerts.append(("Unencrypted traffic", "Plaintext service(s): " + ", ".join(plain)))
    dns = int((df["dst_port"] == 53).sum())
    if dns >= DNS_VOLUME:
        alerts.append(("DNS volume", f"{dns} DNS packets - possible tunneling"))
    return alerts


def render(df, duration, model):
    if df.empty:
        st.warning("No IP packets captured. Browse a page and scan again.")
        return
    df = df.copy(); df["service"] = df["dst_port"].apply(service_name)
    alerts = detect(df, duration)

    geo_on = st.session_state.get("geo_on", True)
    if geo_on:
        with st.spinner("Looking up destination locations..."):
            geo = geolocate(list(df["destination"].unique()))
        df["country"] = df["destination"].map(lambda ip: geo.get(ip, {}).get("country", "?"))

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Packets", len(df)); c2.metric("Destinations", df["destination"].nunique())
    c3.metric("Data", f"{df['size'].sum()/1024:.1f} KB"); c4.metric("Rule alerts", len(alerts))

    if alerts:
        for cat, msg in alerts:
            (st.error if SEVERITY.get(cat) == "high" else st.warning)(f"**{cat}** - {msg}")
    else:
        st.success("No suspicious patterns from rule-based detection.")

    if geo_on:
        st.divider()
        st.subheader("Where your traffic is going")
        my_loc = get_my_location()
        dests = [{"lat": geo[ip]["lat"], "lon": geo[ip]["lon"],
                  "label": f"{ip} ({geo[ip].get('city') or geo[ip].get('country', '')})"}
                 for ip in df["destination"].unique()
                 if geo.get(ip, {}).get("lat") is not None]
        if my_loc and dests:
            st.plotly_chart(traffic_map(my_loc, dests), use_container_width=True)
            st.caption(f"Lines run from your approximate location "
                       f"({my_loc.get('city', '?')}, {my_loc.get('country', '?')}) to each destination.")
        elif dests:
            st.map(pd.DataFrame([{"lat": d["lat"], "lon": d["lon"]} for d in dests]))
            st.caption("Couldn't pin your location, so showing destinations only.")
        else:
            st.info("No locatable public destinations in this capture.")
        known = df[~df["country"].isin(["Local network", "Unknown", "Lookup failed", "?"])]
        if not known.empty:
            st.caption("Connections by country")
            st.bar_chart(known["country"].value_counts())

    st.divider()
    st.subheader("Experimental ML verdict (per connection)")
    if model is None:
        st.info("live_model.joblib not found - run  python train_live.py  first.")
    else:
        feats, keys = to_features(df)
        scores = model.predict_proba(feats)[:, 1]
        ml = pd.DataFrame(keys, columns=["source", "destination"])
        ml["ml_attack_score"] = scores.round(3)
        ml["ml_verdict"] = ["suspicious" if s >= 0.5 else "normal" for s in scores]
        st.caption("Experimental: model trained on 1998-era NSL-KDD, so it over-flags modern traffic.")
        st.dataframe(ml.sort_values("ml_attack_score", ascending=False),
                     use_container_width=True, hide_index=True)

    st.divider()
    a, b = st.columns(2)
    with a:
        st.subheader("Protocol mix"); st.bar_chart(df["protocol"].value_counts())
    with b:
        st.subheader("Top services"); st.bar_chart(df["service"].value_counts().head(8))

    st.subheader("Captured connections")
    cols = ["source", "destination", "protocol", "service", "size"]
    if "country" in df.columns:
        cols.append("country")
    st.dataframe(df[cols], use_container_width=True, hide_index=True)
    st.download_button("Download report (CSV)", df.to_csv(index=False).encode("utf-8"),
                       file_name="capture_report.csv", mime="text/csv")


# ---------------- UI ----------------
model = load_live_model()
st.title("Live Network Traffic Monitor")
st.caption("Real packet capture - rules + experimental ML + geolocation")

st.subheader("Your network")
iface, link = get_active_interface()
net_df = pd.DataFrame({
    "Property": ["Device", "Local IP", "Wi-Fi (SSID)", "Interface", "Link speed"],
    "Value": [socket.gethostname(), get_local_ip(), get_wifi_ssid(), iface, link],
})
st.table(net_df.set_index("Property"))

st.subheader("Network speed")
if "speed_history" not in st.session_state:
    st.session_state.speed_history = []
if st.button("Measure live throughput"):
    with st.spinner("Sampling 1 second..."):
        down, up = measure_throughput()
    st.session_state.speed_history.append({"Download": down, "Upload": up})
    st.session_state.speed_history = st.session_state.speed_history[-20:]
if st.session_state.speed_history:
    latest = st.session_state.speed_history[-1]
    peak = max(max(h["Download"], h["Upload"]) for h in st.session_state.speed_history)
    max_val = max(200, peak * 1.25)
    g1, g2 = st.columns(2)
    g1.plotly_chart(speed_gauge("Download", latest["Download"], max_val), use_container_width=True)
    g2.plotly_chart(speed_gauge("Upload", latest["Upload"], max_val), use_container_width=True)
    st.caption("Throughput history (last 20 readings, KB/s)")
    st.line_chart(pd.DataFrame(st.session_state.speed_history))

st.divider()
duration = st.sidebar.slider("Capture window (seconds)", 3, 20, 5)
geo_on = st.sidebar.checkbox("Show destination locations (GeoIP)", value=True)
st.session_state["geo_on"] = geo_on
live = st.sidebar.toggle("Live mode (auto-refresh)", value=False)
st.sidebar.caption("Live mode keeps capturing on a loop. Untick to stop.")

if live:
    render(capture(duration), duration, model)
    time.sleep(0.5); st.rerun()
else:
    col_a, col_b = st.columns(2)
    scan = col_a.button("Scan my network now")
    demo = col_b.button("Run attack simulation (demo)")
    if scan:
        render(capture(duration), duration, model)
    elif demo:
        st.info("Showing SIMULATED attack traffic (a fabricated port scan + flood). "
                "No real device is scanned - this is a safe demo of the detection logic.")
        render(simulated_capture(), 5, model)