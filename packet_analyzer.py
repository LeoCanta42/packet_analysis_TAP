from pyspark.sql import SparkSession
from pyspark.conf import SparkConf

elastic_index = "packets"

# Elastic conf
sparkConf = SparkConf().set("es.nodes", "elasticsearch") \
                        .set("es.port", "9200")

# Initialize SparkSession
spark = SparkSession.builder.appName("KafkaSparkIntegration").getOrCreate()

spark.sparkContext.setLogLevel("ERROR")

# Read from Kafka
df = spark.readStream.format("kafka") \
    .option("kafka.bootstrap.servers", "kafkaserver:9092") \
    .option("subscribe", "packets") \
    .load()

df = df.selectExpr("CAST(timestamp AS STRING)", "CAST(value AS STRING)") \

df.writeStream \
    .format("es") \
    .start(elastic_index) \
    .awaitTermination()