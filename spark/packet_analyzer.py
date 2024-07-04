from pyspark.sql import SparkSession
from pyspark.conf import SparkConf
from pyspark.ml.feature import VectorAssembler
from pyspark.sql.functions import col, from_json, unix_timestamp, window, count, avg, to_timestamp
from pyspark.sql.types import StructType, StructField, StringType, ArrayType, IntegerType, DoubleType
import geoip2.database
import requests
from ipaddress import ip_address, ip_network
import dns.resolver
from joblib import load


################################
# Anomaly detection with model #
################################

################################
#   IP type classification     #
################################

# Define private IP ranges
private_ipv4_ranges = [
    ip_network('10.0.0.0/8'),
    ip_network('172.16.0.0/12'),
    ip_network('192.168.0.0/16'),
    ip_network('127.0.0.0/8'),
    ip_network('169.254.0.0/16'),
    ip_network('224.0.0.0/4'),
    ip_network('0.0.0.0/8'),
    ip_network('2001:db8::/32'),
]

private_ipv6_ranges = [
    ip_network('fc00::/7'),
    ip_network('fe80::/10'),
    ip_network('ff00::/8'),
]

def is_private_ip(ip):
    if ip is None:
        return False
    ip = ip_address(ip)
    if ip.version == 4:
        return any(ip in net for net in private_ipv4_ranges)
    elif ip.version == 6:
        return any(ip in net for net in private_ipv6_ranges)
    return False

# Convert IP addresses to numeric
def ip_to_int(ip):
    try:
        return int(ip_address(ip))
    except:
        return None

################################
#        Geolocation           #
################################
# Take the geolocalization from the IP using local GeoLite2-DB
def get_geolocation_geo2(ip):
    if is_private_ip(ip):
        return "Special or private IP Address - No Geolocation"
    else:
        try:
            reader = geoip2.database.Reader('GeoLite2-City.mmdb')
            response = reader.country(ip)
            return response.country.name
        except:
            return "Unknown"

# Take the geolocalization from the IP using db-ip.com
def get_geolocation_dbip(ip):
    if is_private_ip(ip):
        return "Special or private IP Address - No Geolocation"
    else:
        url = f"https://api.db-ip.com/v2/free/{ip}"
        response = requests.get(url)
        return response.json()

################################
#        IP Threat             #
################################

# Check if the IP is a threat
def check_ip_threat(ip):
    #open a file to get the key
    with open('abuseipdb.key', 'r') as file:
        key = file.read().replace('\n', '')
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {'Key': key, 'Accept': 'application/json'}
    response = requests.get(url, headers=headers)
    return response.json()
    

################################
#    Application detection     #
################################

# Application protocol detetion
def application_detection(port):
    # Dictionary mapping ports to application protocols
    port_protocol_map = {
        20: 'FTP (Data)',
        21: 'FTP (Control)',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        587: 'SMTP (Secure)',
        993: 'IMAP (Secure)',
        995: 'POP3 (Secure)',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP (Alternate)',
    }
    
    # Retrieve the protocol for the given port or return 'Unknown' if not found
    return port_protocol_map.get(port, 'Unknown')

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
    elastic_index = "packets"
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

    # PARSE THE JSON
    df = df.selectExpr("CAST(timestamp AS STRING) AS timestamp", "CAST(value AS STRING) AS value")
    df = df.select(from_json(col("value"), schema).alias("data")).select("data.*")

    # # TAKE POSITION FROM THE IP
    # get_geolocation_udf = spark.udf.register("get_geolocation", get_geolocation_dbip)
    # df = df.withColumn("src_position", get_geolocation_udf(col("layers.ip.ip_ip_src")))
    # df = df.withColumn("dst_position", get_geolocation_udf(col("layers.ip.ip_ip_dst")))

    # # CHECK IF THE IP IS A THREAT
    # check_ip_threat_udf = spark.udf.register("check_ip_threat", check_ip_threat)
    # df = df.withColumn("src_threat", check_ip_threat_udf(col("layers.ip.ip_ip_src")))
    # df = df.withColumn("dst_threat", check_ip_threat_udf(col("layers.ip.ip_ip_dst")))

    # # APPLICATION LAYER PROTOCOL
    # application_detection_udf = spark.udf.register("application_detection", application_detection)
    # df = df.withColumn("tcp_src_application_protocol", application_detection_udf(col("layers.tcp.tcp_tcp_srcport")))
    # df = df.withColumn("tcp_dst_application_protocol", application_detection_udf(col("layers.tcp.tcp_tcp_dstport")))
    # df = df.withColumn("udp_src_application_protocol", application_detection_udf(col("layers.udp.udp_udp_srcport")))
    # df = df.withColumn("udp_dst_application_protocol", application_detection_udf(col("layers.udp.udp_udp_dstport")))


    # ANOMALY DETECTION WITH MODEL

    # Load the model
    model = load('iforest_model.joblib')

    # Convert frame_time of 2024-07-04T08:08:08.675009933Z format to timestamp
    df = df.withColumn("frame_time", to_timestamp(col("layers.frame.frame_frame_time"), "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSS'Z'"))

    # Add a watermark for the frame_time column
    df = df.withWatermark("frame_time", "1 minute")

    # Cast ip_ip_len and frame_frame_len to IntegerType
    tDf = df.withColumn("frame_time",col("frame_time"))
    tDf = df.withColumn("layers.ip.ip_ip_len", col("layers.ip.ip_ip_len").cast(IntegerType()))
    tDf = df.withColumn("layers.frame.frame_frame_len", col("layers.frame.frame_frame_len").cast(IntegerType()))

    # Group with time, ip_src, frame_protocols and calculate matrix
    # gDf = tDf.groupBy(
    #     window(col("frame_time"), "20 seconds").alias("time_window"),
    #     col("layers.ip.ip_ip_src").alias("ip_src"),
    #     col("layers.frame.frame_frame_protocols").alias("frame_protocols")
    # ).agg(
    #     count("*").alias("count"),
    #     avg("layers.ip.ip_ip_len").alias("ip_avg_len"),
    #     avg("layers.frame.frame_frame_len").alias("frame_avg_len"),
    #     (avg("layers.ip.ip_ip_len") / max("layers.ip.ip_ip_len")).alias("ip_local_anomaly"),
    #     (avg("layers.frame.frame_frame_len") / max("layers.frame.frame_frame_len")).alias("frame_local_anomaly")
    # ).withColumn("start", col("time_window").getItem("start")).withColumn("end", col("time_window").getItem("end"))
    
    # Simplified aggregation: count packets per IP source
    gDf = tDf.withWatermark("frame_time", "1 minute"). \
    groupBy(
        window(col("frame_time"), "10 seconds").alias("time_window"),
        col("layers.ip.ip_ip_src").alias("ip_src")
    ).agg(
        count("*").alias("packet_count")
    )

    raw_console = gDf.writeStream.outputMode("append").format("console").start()
    raw_console.awaitTermination()

    gDf = gDf.withWatermark("start", "1 minute")

    # Alias DataFrames to avoid ambiguity
    tDf_alias = tDf.alias("tDf")
    gDf_alias = gDf.alias("gDf")

    # Join tDf and gDf on ip_src, frame_protocols, frame_time (in range of start and end)
    cond = (tDf_alias["layers.ip.ip_ip_src"] == gDf_alias["ip_src"]) & \
              (tDf_alias["layers.frame.frame_frame_protocols"] == gDf_alias["frame_protocols"]) & \
                (tDf_alias["frame_time"] >= gDf_alias["start"]) & \
                (tDf_alias["frame_time"] <= gDf_alias["end"])
    
    jDf = tDf_alias.join(gDf_alias, cond, "left").select(
        tDf_alias["layers.ip.ip_ip_src"],
        tDf_alias["layers.ip.ip_ip_dst"],
        tDf_alias["layers.ip.ip_ip_len"],
        tDf_alias["layers.tcp.tcp_tcp_srcport"],
        tDf_alias["layers.tcp.tcp_tcp_dstport"],
        tDf_alias["layers.frame.frame_frame_protocols"],
        tDf_alias["layers.frame.frame_frame_len"],
        tDf_alias["frame_time"],
        gDf_alias["ip_avg_len"],
        gDf_alias["frame_avg_len"],
        gDf_alias["ip_local_anomaly"],
        gDf_alias["frame_local_anomaly"],
        gDf_alias["count"]
    )

    # Add feature column using VectorAssembler
    cols = ["ip_avg_len", "frame_avg_len", "ip_local_anomaly", "frame_local_anomaly", "count"]
    assembler = VectorAssembler(inputCols=cols, outputCol="features")
    fDf = assembler.transform(jDf)

    # Use the model to make predictions
    predict_udf = spark.udf.register("predict",lambda features: float(model.decision_function([features.toArray()])[0]), DoubleType())
    anomaly_udf = spark.udf.register("anomaly",lambda features: int(model.predict([features.toArray()])[0]), IntegerType())
    
    result_df = fDf.withColumn("anomaly_score", predict_udf(col("features")))
    result_df = result_df.withColumn("anomaly", anomaly_udf(col("features")))

    #OUTPUT

    # Print to console debug
    console = result_df.writeStream.outputMode("append").format("console").start()
    console.awaitTermination()

    # Write to Elastic
    elastic = df.writeStream \
        .option("checkpointLocation", "/tmp/") \
        .format("es") \
        .start(elastic_index)
    elastic.awaitTermination()
    

if __name__ == "__main__":
    main()