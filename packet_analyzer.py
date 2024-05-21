from pyspark.sql import SparkSession

print("Starting packet analyzer...")
# Initialize SparkSession
spark = SparkSession.builder.appName("KafkaSparkIntegration").getOrCreate()

# Read from Kafka
df = spark.readStream.format("kafka") \
    .option("kafka.bootstrap.servers", "kafkaserver:9092") \
    .option("subscribe", "packets") \
    .load()

# Process the data (this is a simple example)
df = df.selectExpr("CAST(key AS STRING)", "CAST(value AS STRING)")

df.writeStream.format("console").start().awaitTermination()