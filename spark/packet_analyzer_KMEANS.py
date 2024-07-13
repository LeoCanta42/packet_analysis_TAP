from pyspark.sql import SparkSession
from pyspark.conf import SparkConf
from pyspark.ml.feature import VectorAssembler
from pyspark.ml.linalg import Vectors, VectorUDT
from pyspark.sql.functions import col, from_json, when, udf
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
feature_names = joblib.load('feature_names.pkl')

# Define UDF to predict clusters and compute distances
#OLDONE
# def predict_and_distance(features_vec):
#     cluster = kmeans.predict([features_vec])
#     center = kmeans.cluster_centers_[cluster[0]]
#     distance = np.linalg.norm(features_vec - center)
#     return (cluster[0], distance)
#NEWONE
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
    
    # Parse the JSON data and apply schema
    parsed_df = df.select(from_json(col("value").cast("string"), schema).alias("data")).select("data.*")

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
    threshold = 3.0  # Adjust based on your model
    final = predictions_df.withColumn("anomaly", when(col("prediction.distance") > threshold, 1).otherwise(0))

    # Print to console debug
    console = final.writeStream.outputMode("append").format("console").start()
    console.awaitTermination()
    

if __name__ == "__main__":
    main()
