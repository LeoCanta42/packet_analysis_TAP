from pyspark.sql import SparkSession

print("*** Starting packet analyzer...\n\n")
# Initialize SparkSession
spark = SparkSession.builder.appName("KafkaSparkIntegration").getOrCreate()

spark.sparkContext.setLogLevel("ERROR")

# Read from Kafka
df = spark.readStream.format("kafka") \
    .option("kafka.bootstrap.servers", "kafkaserver:9092") \
    .option("subscribe", "packets") \
    .load()

#print packets to console
query = df.writeStream.outputMode("append").format("console").start()
query.awaitTermination()

print("*** Closing packet analyzer...\n\n")