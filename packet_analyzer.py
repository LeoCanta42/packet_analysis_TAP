from pyspark.sql import SparkSession
from pyspark.sql.functions import col, concat, lit

scala_version = '2.12'  # TODO: Ensure this is correct
spark_version = '3.2.1'
packages = [
    f'org.apache.spark:spark-sql-kafka-0-10_{scala_version}:{spark_version}',
    'org.apache.kafka:kafka-clients:3.2.0'
]
spark = SparkSession.builder\
   .master("local")\
   .appName("kafka-example")\
   .config("spark.jars.packages", ",".join(packages))\
   .getOrCreate()

def main():
    kafkaDf = spark.read.format("kafka")\
    .option("kafka.bootstrap.servers", "PLAINTEXT://kafkaserver:9092")\
    .option("subscribe", "packets")\
    .option("startingOffsets", "earliest")\
    .load()
    kafkaDf.select(
        concat(col("topic"), lit(':'), col("partition").cast("string")).alias("topic_partition"),
        col("offset"),
        col("value").cast("string")
    ).show()