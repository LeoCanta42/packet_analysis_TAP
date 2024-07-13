import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
import json
import joblib

# Load and parse the data
def parse_json(log_file):
    with open(log_file, 'r') as file:
        data = []
        for line in file:
            if '{"index":' in line:
                continue
            data.append(json.loads(line))
    return data

data = parse_json('../packets.log')

# Extract features
features = []
for packet in data:
    layer = packet['layers']
    frame = layer.get('frame', {})
    eth = layer.get('eth', {})
    ip = layer.get('ip', {})
    tcp = layer.get('tcp', None)  # Use None as default if missing
    udp = layer.get('udp', None)  # Use None as default if missing

    frame_len = int(frame.get('frame_frame_len', 0))
    protocols = frame.get('frame_frame_protocols', '').split(':')
    ip_len = int(ip.get('ip_ip_len', 0))
    ip_proto = int(ip.get('ip_ip_proto', 0)) if ip.get('ip_ip_proto') else 0

    # If both TCP and UDP are missing, skip this packet
    if tcp is None and udp is None:
        continue

    tcp_srcport = int(tcp.get('tcp_tcp_srcport', 0)) if tcp else 0
    tcp_dstport = int(tcp.get('tcp_tcp_dstport', 0)) if tcp else 0
    udp_srcport = int(udp.get('udp_udp_srcport', 0)) if udp else 0
    udp_dstport = int(udp.get('udp_udp_dstport', 0)) if udp else 0

    features.append([frame_len, ip_len, ip_proto, tcp_srcport, tcp_dstport, udp_srcport, udp_dstport])

# Convert to DataFrame
df = pd.DataFrame(features, columns=['frame_len', 'ip_len', 'ip_proto', 'tcp_srcport', 'tcp_dstport', 'udp_srcport', 'udp_dstport'])

# Fill missing values with 0
df.fillna(0, inplace=True)

# Normalize the data
scaler = StandardScaler()
X_scaled = scaler.fit_transform(df)

# Train the K-Means model
k = 3  # Choose an appropriate value for k
kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
kmeans.fit(X_scaled)

# Save the models for later use
joblib.dump(scaler, 'scaler_model.pkl')
joblib.dump(kmeans, 'kmeans_model.pkl')
