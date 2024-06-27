from ipaddress import ip_address
import pandas as pd
from pyod.models.iforest import IForest
from pyspark.sql import SparkSession
from pyspark.sql.functions import col
from pyspark.sql.types import StructType, StructField, StringType, IntegerType
import pickle
from pyspark.sql.functions import when

# Define the schema
frame_schema = StructType([
    StructField("frame_frame_time", StringType(), True),
    StructField("frame_frame_number", StringType(), True),
    StructField("frame_frame_len", StringType(), True),
    StructField("frame_frame_protocols", StringType(), True)
])

eth_schema = StructType([
    StructField("eth_eth_src", StringType(), True),
    StructField("eth_eth_dst", StringType(), True),
    StructField("eth_eth_type", StringType(), True)
])

ip_schema = StructType([
    StructField("ip_ip_src", StringType(), True),
    StructField("ip_ip_dst", StringType(), True),
    StructField("ip_ip_proto", StringType(), True)
])

udp_schema = StructType([
    StructField("udp_udp_srcport", StringType(), True),
    StructField("udp_udp_dstport", StringType(), True)
])

dns_schema = StructType([
    StructField("dns_dns_qry_name", StringType(), True),
    StructField("dns_dns_qry_type", StringType(), True),
    StructField("dns_dns_qry_class", StringType(), True),
    StructField("dns_dns_resp_name", StringType(), True),
    StructField("dns_dns_resp_type", StringType(), True),
    StructField("dns_dns_resp_class", StringType(), True)
])

# Define the root schema
schema = StructType([
    StructField("timestamp", StringType(), True),
    StructField("layers", StructType([
        StructField("frame", frame_schema, True),
        StructField("eth", eth_schema, True),
        StructField("ip", ip_schema, True),
        StructField("udp", udp_schema, True),
        StructField("dns", dns_schema, True)
    ]), True)
])

# Initialize Spark session
spark = SparkSession.builder.appName("TrainAnomalyDetectionModel").getOrCreate()

# Load data
df = spark.read.json("../packets.log", schema=schema)

# Select relevant fields and preprocess them
df_selected = df.selectExpr(
    "cast(layers.frame.frame_frame_time as double) as frame_time",
    "cast(layers.frame.frame_frame_len as int) as frame_len",
    "cast(layers.eth.eth_eth_type as int) as eth_type",
    "layers.ip.ip_ip_src as ip_src",
    "layers.ip.ip_ip_dst as ip_dst",
    "cast(layers.ip.ip_ip_proto as int) as ip_proto",
    "cast(layers.udp.udp_udp_srcport as int) as udp_srcport",
    "cast(layers.udp.udp_udp_dstport as int) as udp_dstport",
    "layers.dns.dns_dns_qry_name as dns_qry_name",
    "cast(layers.dns.dns_dns_qry_type as int) as dns_qry_type",
    "cast(layers.dns.dns_dns_qry_class as int) as dns_qry_class"
)

# Convert IP addresses to numeric
def ip_to_int(ip):
    try:
        return int(ip_address(ip))
    except:
        return None

udf_ip_to_int = spark.udf.register("ip_to_int", ip_to_int, IntegerType())
df_selected = df_selected.withColumn("ip_src", udf_ip_to_int(col("ip_src")))
df_selected = df_selected.withColumn("ip_dst", udf_ip_to_int(col("ip_dst")))

# Handle missing values (example: fill with -1)
df_selected = df_selected.na.fill(-1)

# Convert to Pandas DataFrame for training
features = df_selected.toPandas()

# Ensure all columns are numeric
features = features.apply(pd.to_numeric, errors='coerce')

# Handle NaN values in Pandas DataFrame
features = features.fillna(-1)  # Example: Fill NaN with -1

# Train PyOD model
data = features.values
clf = IForest()
clf.fit(data)

# Save the trained model
with open("anomaly_detection_model.pkl", "wb") as f:
    pickle.dump(clf, f)
