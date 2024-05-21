from pyspark.sql import SparkSession

print("*** Starting test...\n\n")
# Initialize SparkSession
spark = SparkSession.builder.appName("TestSpark").getOrCreate()

# Read from file packets.log that is an array of jsons
df = spark.read.json("packets.log")

#Print result
print(df)

print("*** Closing test...\n\n")