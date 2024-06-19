from pyspark.sql import SparkSession
from pyspark.conf import SparkConf
from pyspark.sql.functions import col, from_json
from pyspark.sql.types import StructType, StructField, StringType, BooleanType, ArrayType
import geoip2.database
import requests
from pyod.models.knn import KNN
import numpy as np

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
        StructField("dns", dns_schema, True)
    ]), True)
])

# Take the geolocalization from the IP using local GeoLite2-DB
def get_geolocation(ip):
    try:
        reader = geoip2.database.Reader('GeoLite2-Country.mmdb')
        response = reader.country(ip)
        return response.country.name
    except:
        return "Unknown"

# Take the geolocalization from the IP using db-ip.com
def get_geolocation_dbip(ip):
    url = f"https://api.db-ip.com/v2/free/{ip}"
    response = requests.get(url)
    return response.json()

# Check if the IP is a threat
def check_ip_threat(ip):
    #open a file to get the key
    with open('abuseipdb.key', 'r') as file:
        key = file.read().replace('\n', '')
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {'Key': key, 'Accept': 'application/json'}
    response = requests.get(url, headers=headers)
    return response.json()
    
def main():
    elastic_index = "packets"

    # Elastic conf
    sparkConf = SparkConf().set("es.nodes", "elasticsearch") \
                            .set("es.port", "9200")

    # Initialize SparkSession
    spark = SparkSession.builder.appName("KafkaSparkIntegration").config(conf=sparkConf).getOrCreate()

    spark.sparkContext.setLogLevel("ERROR")

    # Read from Kafka
    df = spark.readStream.format("kafka") \
        .option("kafka.bootstrap.servers", "kafkaserver:9092") \
        .option("subscribe", "packets") \
        .load()

    # Parse the JSON
    df = df.selectExpr("CAST(timestamp AS STRING) AS timestamp", "CAST(value AS STRING) AS value")
    df = df.select(from_json(col("value"), schema).alias("data")).select("data.*")

    # Take position from the IP
    get_geolocation_udf = spark.udf.register("get_geolocation", get_geolocation_dbip)

    df = df.withColumn("src_position", get_geolocation_udf(col("layers.ip.ip_ip_src")))
    df = df.withColumn("dst_position", get_geolocation_udf(col("layers.ip.ip_ip_dst")))

    # Check if the IP is a threat
    check_ip_threat_udf = spark.udf.register("check_ip_threat", check_ip_threat)

    df = df.withColumn("src_threat", check_ip_threat_udf(col("layers.ip.ip_ip_src")))
    df = df.withColumn("dst_threat", check_ip_threat_udf(col("layers.ip.ip_ip_dst")))

    # Print to console debug
    console = df.writeStream.outputMode("append").format("console").start()
    console.awaitTermination()

    # Write to Elastic
    elastic = df.writeStream \
        .option("checkpointLocation", "/tmp/") \
        .format("es") \
        .start(elastic_index)
    elastic.awaitTermination()
    

if __name__ == "__main__":
    main()