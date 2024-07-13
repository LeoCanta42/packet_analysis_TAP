from pyspark.sql import SparkSession
from pyspark.conf import SparkConf
from pyspark.ml.feature import VectorAssembler
from pyspark.ml.linalg import Vectors, VectorUDT
from pyspark.sql.functions import col, from_json, when, pandas_udf
from pyspark.sql.types import StructType, StructField, StringType, ArrayType, IntegerType, FloatType, StructType
import joblib
import numpy as np
import pandas as pd

################################
# Anomaly detection with model #
################################

# Load the pre-trained models
scaler = joblib.load('scaler_model.pkl')
kmeans = joblib.load('kmeans_model.pkl')

# Define UDF to predict clusters and compute distances
@pandas_udf("array<float>")
def predict_and_distance_udf(features_vec: pd.Series) -> pd.Series:
    results = features_vec.apply(lambda x: predict_and_distance(np.array(x)))
    return results.apply(pd.Series)

def predict_and_distance(features_vec):
    cluster = kmeans.predict([features_vec])
    center = kmeans.cluster_centers_[cluster[0]]
    distance = np.linalg.norm(features_vec - center)
    return [float(cluster[0]), float(distance)]

# Define UDF to extract features
@pandas_udf("array<int>")
def extract_features_udf(layer: pd.Series) -> pd.Series:
    results = layer.apply(extract_features)
    return results.apply(pd.Series)

def extract_features(layer):
    frame = layer.get('frame', {})
    ip = layer.get('ip', {})
    tcp = layer.get('tcp', {})
    udp = layer.get('udp', {})

    frame_len = int(frame.get('frame_frame_len', 0)) if frame.get('frame_frame_len') else 0
    ip_len = int(ip.get('ip_ip_len', 0)) if ip.get('ip_ip_len') else 0
    ip_proto = int(ip.get('ip_ip_proto', 0)) if ip.get('ip_ip_proto') else 0
    tcp_srcport = int(tcp.get('tcp_tcp_srcport', 0)) if tcp.get('tcp_tcp_srcport') else 0
    tcp_dstport = int(tcp.get('tcp_tcp_dstport', 0)) if tcp.get('tcp_tcp_dstport') else 0
    udp_srcport = int(udp.get('udp_udp_srcport', 0)) if udp.get('udp_udp_srcport') else 0
    udp_dstport = int(udp.get('udp_udp_dstport', 0)) if udp.get('udp_udp_dstport') else 0

    return [frame_len, ip_len, ip_proto, tcp_srcport, tcp_dstport, udp_srcport, udp_dstport]

# Define UDF to scale features
@pandas_udf("array<float>")
def scale_features_udf(features: pd.Series) -> pd.Series:
    results = features.apply(scale_features)
    return results.apply(pd.Series)

def scale_features(features):
    return scaler.transform([features]).tolist()[0]

# Define UDF to transform to vector
@pandas_udf(VectorUDT())
def to_vector_udf(features: pd.Series) -> pd.Series:
    results = features.apply(to_vector)
    return results

def to_vector(features):
    return Vectors.dense(features)

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
    sparkConf = SparkConf().set("es.nodes", "elasticsearch") \
                            .set("es.port", "9200")\
                            .set("es.index.auto.create", "true")

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
                                              
    # ANOMALY DETECTION WITH MODEL

    # Apply UDFs
    features_df = df.withColumn("features", extract_features_udf(col("layers")))
    scaled_df = features_df.withColumn("scaled_features", scale_features_udf(col("features")))
    vectorized_df = scaled_df.withColumn("features_vec", to_vector_udf(col("scaled_features")))

    # Use the model to make predictions
    predictions_df = vectorized_df.withColumn("prediction", predict_and_distance_udf(col("features_vec")))

    # Define a threshold and filter anomalies
    threshold = 1.0  # Adjust based on your model
    final = predictions_df.withColumn("anomaly_score", col("prediction").getItem(1)) \
                          .withColumn("anomaly", when(col("prediction").getItem(1) > threshold, 1).otherwise(0))

    # Print to console debug
    console = final.writeStream.outputMode("append").format("console").start()
    console.awaitTermination()
    

if __name__ == "__main__":
    main()
