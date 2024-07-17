from pyspark.sql import SparkSession
from pyspark.conf import SparkConf
from pyspark.ml.linalg import Vectors, VectorUDT
from pyspark.sql.functions import col, from_json, when, udf, from_unixtime, date_format
from pyspark.sql.types import StructType, StructField, StringType, ArrayType, IntegerType, FloatType, StructType
import joblib
import numpy as np
import pandas as pd
import requests
from elasticsearch import Elasticsearch


################################
#       Global variables       #
################################

LOCAL_IP="192.168.3.105"
ELASTIC_INDEX = "packets"

################################
#       Elastic setup map      #
################################
def setup_elastic():
    global ELASTIC_INDEX

    es=Elasticsearch([{'host':'elasticsearch','port':9200, 'scheme':'http'}])
    mapping = {
        "mappings": {
            "properties": {
                "src_coordinates": {
                    "type": "geo_point"
                },
                "dst_coordinates": {
                    "type": "geo_point"
                }
            }
        }
    }
    # Create the index with the defined mapping
    if not es.indices.exists(index=ELASTIC_INDEX):
        es.indices.create(index=ELASTIC_INDEX, body=mapping)

################################
# Anomaly detection with model #
################################

# Load the pre-trained models
scaler = joblib.load('scaler_model.pkl')
kmeans = joblib.load('kmeans_model.pkl')
feature_names = joblib.load('feature_names.pkl')

# Define UDF to predict clusters and compute distances
def predict_and_distance(features_vec):
    features_vec = np.array(features_vec)
    cluster = int(kmeans.predict([features_vec])[0])
    center = kmeans.cluster_centers_[cluster]
    distance = float(np.linalg.norm(features_vec - center))
    return cluster, distance

# Extract features for prediction
def extract_features(layers):
    frame = layers.frame
    ip = layers.ip
    tcp = layers.tcp
    udp = layers.udp

    frame_len = int(frame.frame_frame_len, 0) if frame else 0
    ip_len = int(ip.ip_ip_len, 0) if ip else 0
    ip_proto = int(ip.ip_ip_proto, 0) if ip else 0
    tcp_srcport = int(tcp.tcp_tcp_srcport, 0) if tcp else 0
    tcp_dstport = int(tcp.tcp_tcp_dstport, 0) if tcp else 0
    udp_srcport = int(udp.udp_udp_srcport, 0) if udp else 0
    udp_dstport = int(udp.udp_udp_dstport, 0) if udp else 0

    return [frame_len, ip_len, ip_proto, tcp_srcport, tcp_dstport, udp_srcport, udp_dstport]
# Scale features
def scale_features(features):
    df_features = pd.DataFrame([features], columns=feature_names)
    return scaler.transform(df_features).tolist()[0]
# Transform to vector column required by kmeans
def to_vector(features):
    return Vectors.dense(features)

################################
#        Geolocation           #
################################

geolocation_cache = {}

# Take the geolocalization from the IP using ipinfo.io
def get_geolocation_ipinfo(ip):
    if ip in geolocation_cache:
        return geolocation_cache[ip]
    else:
        if ip==LOCAL_IP or ip=="127.0.0.1":
            geolocation_cache[ip]={"city":"LOCAL","loc":[0.0,0.0]}
        else:
            try:
                with open('ipinfotoken.key', 'r') as file:
                    token = file.read().replace('\n', '')
                    url = f"https://ipinfo.io/{ip}?token={token}"
                    response = requests.get(url)
                    json=response.json()
                    city='"{}"'.format(json.get("city"))
                    #we need to parse to a geoinfo format for kibana map -> [longitude,latitude]
                    location=json.get("loc").split(",")
                    location=[float(location[1]),float(location[0])]
        
                    geolocation_cache[ip]={"city":city,"loc":location}
            except:
                return {"city":"ERROR","loc":[0.0,0.0]}
        return geolocation_cache[ip]

################################
#    Application detection     #
################################

# Application protocol detetion
def application_detection(port):
    # Dictionary mapping ports to application protocols
    port_protocol_map = {
        '20': 'FTP (Data)',
        '21': 'FTP (Control)',
        '22': 'SSH',
        '23': 'Telnet',
        '25': 'SMTP',
        '53': 'DNS',
        '80': 'HTTP',
        '110': 'POP3',
        '143': 'IMAP',
        '443': 'HTTPS',
        '587': 'SMTP (Secure)',
        '993': 'IMAP (Secure)',
        '995': 'POP3 (Secure)',
        '3306': 'MySQL',
        '3389': 'RDP',
        '5432': 'PostgreSQL',
        '5900': 'VNC',
        '6379': 'Redis',
        '8080': 'HTTP (Alternate)',
    }
    
    # Retrieve the protocol for the given port or return 'Unknown' if not found
    return port_protocol_map.get(port, 'Unknown')

def application_extraction(protocols_list):
    protocols = protocols_list.split(":")
    for protocol in protocols:
        if protocol == "http":
            return "HTTP"
        elif protocol == "tls":
            return "HTTPS"
        elif protocol == "dns":
            return "DNS"
        elif protocol == "smtp":
            return "SMTP"
        elif protocol == "ftp":
            return "FTP"
        elif protocol == "pop3":
            return "POP3"
        elif protocol == "imap":
            return "IMAP"
        elif protocol == "ssh":
            return "SSH"
        elif protocol == "telnet":
            return "Telnet"
        elif protocol == "mysql":
            return "MySQL"
        elif protocol == "rdp":
            return "RDP"
        elif protocol == "postgresql":
            return "PostgreSQL"
        elif protocol == "vnc":
            return "VNC"
        elif protocol == "redis":
            return "Redis"
        elif protocol == "ftp":
            return "FTP"
        elif protocol == "icmp":
            return "ICMP"
    return "Unknown"

################################
#    Defining packet schema    #
################################

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
    StructField("ip_ip_proto", StringType(), True),
    StructField("ip_ip_len", StringType(), True)
])

udp_schema = StructType([
    StructField("udp_udp_srcport", StringType(), True),
    StructField("udp_udp_dstport", StringType(), True)
])

tcp_schema = StructType([
    StructField("tcp_tcp_srcport", StringType(), True),
    StructField("tcp_tcp_dstport", StringType(), True)
])

dns_schema = StructType([
    StructField("dns_dns_qry_name", StringType(), True),
    StructField("dns_dns_qry_type", StringType(), True),
    StructField("dns_dns_qry_class", StringType(), True),
    StructField("dns_dns_resp_name", ArrayType(StringType()), True),
    StructField("dns_dns_resp_type", ArrayType(StringType()), True),
    StructField("dns_dns_resp_class", ArrayType(StringType()), True)
])

# Define the root schema
schema = StructType([
    StructField("timestamp", StringType(), True),
    StructField("layers", StructType([
        StructField("frame", frame_schema, True),
        StructField("eth", eth_schema, True),
        StructField("ip", ip_schema, True),
        StructField("udp", udp_schema, True),
        StructField("tcp", tcp_schema, True),
        StructField("dns", dns_schema, True)
    ]), True)
])

################################
#           Main               #
################################

def main():    

    # ELASTIC CONF
    setup_elastic()
    sparkConf = SparkConf().set("es.nodes", "elasticsearch") \
                            .set("es.port", "9200")

    # INITIALIZE SPARKSESSION
    spark = SparkSession.builder.appName("KafkaSparkIntegration").config(conf=sparkConf).getOrCreate()
    spark.sparkContext.setLogLevel("ERROR")

    # READ FROM KAFKA
    df = spark.readStream.format("kafka") \
        .option("kafka.bootstrap.servers", "kafkaserver:9092") \
        .option("subscribe", "packets") \
        .load()
    
    # PARSE THE JSON DATA AND APPLY SCHEMA
    parsed_df = df.select(from_json(col("value").cast("string"), schema).alias("data")).select("data.*")

    # BASE DATA
    parsed_df = parsed_df.withColumn("timestamp", date_format(from_unixtime(col("timestamp")/1000), "yyyy-MM-dd HH:mm:ss"))
    parsed_df = parsed_df.withColumn("ip_src", col("layers.ip.ip_ip_src").cast("string"))
    parsed_df = parsed_df.withColumn("ip_dst", col("layers.ip.ip_ip_dst").cast("string"))
    parsed_df = parsed_df.withColumn("src_port", when(col("layers.tcp.tcp_tcp_srcport").isNotNull(), col("layers.tcp.tcp_tcp_srcport")).otherwise(col("layers.udp.udp_udp_srcport")))
    parsed_df = parsed_df.withColumn("dst_port", when(col("layers.tcp.tcp_tcp_dstport").isNotNull(), col("layers.tcp.tcp_tcp_dstport")).otherwise(col("layers.udp.udp_udp_dstport")))

    # TAKE POSITION FROM THE IP
    get_geolocation_udf = udf(get_geolocation_ipinfo, StructType([
        StructField("city", StringType(), False),
        StructField("loc", ArrayType(FloatType()), False)
    ]))
    parsed_df = parsed_df.withColumn("geoinfo_src", get_geolocation_udf(col("ip_src")))
    parsed_df = parsed_df.withColumn("geoinfo_dst", get_geolocation_udf(col("ip_dst")))

    # PARSE THE POSITION
    parsed_df = parsed_df.withColumn("src_city", col("geoinfo_src").getField("city"))
    parsed_df = parsed_df.withColumn("src_coordinates", col("geoinfo_src").getField("loc"))

    parsed_df = parsed_df.withColumn("dst_city", col("geoinfo_dst").getField("city"))
    parsed_df = parsed_df.withColumn("dst_coordinates", col("geoinfo_dst").getField("loc"))

    # APPLICATION LAYER PROTOCOL
    #First try from protocol, so if we have it we use it
    application_extraction_udf = spark.udf.register("application_extraction", application_extraction)
    parsed_df = parsed_df.withColumn("application_protocol", application_extraction_udf(col("layers.frame.frame_frame_protocols"))) 
    
    #To ensure that application protocol is detected we also try in another way from port
    application_detection_udf = spark.udf.register("application_detection", application_detection)
    parsed_df = parsed_df.withColumn("application_protocol", when(col("application_protocol")=="Unknown",when(application_detection_udf(col("src_port"))!="Unknown", application_detection_udf(col("src_port"))).otherwise(application_detection_udf(col("dst_port")))).otherwise(col("application_protocol")))

    # ANOMALY DETECTION WITH MODEL
    # Extract features and scale them
    extract_features_udf = udf(extract_features, ArrayType(IntegerType()))
    features_df = parsed_df.withColumn("features", extract_features_udf(col("layers")))

    scale_features_udf = udf(scale_features, ArrayType(FloatType()))
    scaled_df = features_df.withColumn("scaled_features", scale_features_udf(col("features")))

    to_vector_udf = udf(to_vector, VectorUDT())
    vectorized_df = scaled_df.withColumn("features_vec", to_vector_udf(col("scaled_features")))

    # Predict clusters and distances
    predict_and_distance_udf = udf(predict_and_distance, StructType([
        StructField("cluster", IntegerType(), False),
        StructField("distance", FloatType(), False)
    ]))
    predictions_df = vectorized_df.withColumn("prediction", predict_and_distance_udf(col("features_vec")))

    # Define a threshold and anomalies
    threshold = 2.6  # Maximum normal traffic is near 2.49 (3.0 should be good)  
    final = predictions_df.withColumn("anomaly", when(col("prediction.distance") > threshold, "ANOMALY").otherwise("NORMAL"))

    # FULL
    only_necessary_columns = final.select("timestamp", "ip_src", "ip_dst", "src_port", "dst_port", "src_city", "dst_city", "src_coordinates", "dst_coordinates", "application_protocol", "anomaly")

    # Print to console debug
    console = only_necessary_columns.writeStream.outputMode("append").format("console").start()

    # Write to Elastic
    elastic = only_necessary_columns.writeStream \
        .option("checkpointLocation", "/tmp/") \
        .format("es") \
        .outputMode("append") \
        .start(ELASTIC_INDEX)
    
    console.awaitTermination()
    elastic.awaitTermination()

if __name__ == "__main__":
    main()
