from pyspark.sql import SparkSession

print("*** Starting packet analyzer...\n\n")
# Initialize SparkSession
spark = SparkSession.builder.appName("KafkaSparkIntegration").getOrCreate()

# Read from Kafka
df = spark.readStream.format("kafka") \
    .option("kafka.bootstrap.servers", "kafkaserver:9092") \
    .option("subscribe", "packets") \
    .load()

print(df)

print("*** Closing packet analyzer...\n\n")