from pyspark.sql import SparkSession
from pyspark.sql.functions import unix_timestamp, window, col, count, avg, max as spark_max, to_timestamp
from pyspark.ml.feature import VectorAssembler
from pyspark.sql.types import StructType, StructField, StringType, DoubleType, IntegerType
import numpy as np
from pyod.models.iforest import IForest
from joblib import dump

# Initialize Spark session
spark = SparkSession.builder \
    .master("local[*]") \
    .appName("lambda") \
    .getOrCreate()

# Define schema for tshark.csv (if not already defined)
schema = StructType([
    StructField("ip_src", StringType(), nullable=True),
    StructField("ip_dst", StringType(), nullable=True),
    StructField("ip_len", DoubleType(), nullable=True),
    StructField("eth_src", StringType(), nullable=True),
    StructField("eth_dst", StringType(), nullable=True),
    StructField("tcp_srcport", IntegerType(), nullable=True),
    StructField("tcp_dstport", IntegerType(), nullable=True),
    StructField("frame_time_epoch", StringType(), nullable=True),
    StructField("frame_len", DoubleType(), nullable=True),
    StructField("frame_protocols", StringType(), nullable=True),
    StructField("frame_time", StringType(), nullable=True)
])

# Read tshark.csv file to DataFrame
df = spark.read.format("csv") \
    .option("header", True) \
    .option("delimiter", "|") \
    .option("mode", "DROPMALFORMED") \
    .schema(schema) \
    .load("tshark.csv") \
    .cache()

# Convert frame_time like Feb  1 2020 03:19:45.377844893 to timestamp
df = df.withColumn("frame_time", to_timestamp(col("frame_time"), "MMM  d yyyy HH:mm:ss.SSSSSSSSS "))

# Add unix timestamp to DataFrame
tDf = df.withColumn("timestamp", unix_timestamp(col("frame_time")))
tDf.show(truncate=False)

# Group with 1 minute time, ip_src, frame_protocols and calculate matrix
gDf = tDf.groupBy(
    window(col("frame_time"), "1 minute").alias("time_window"),
    col("ip_src"),
    col("frame_protocols")
).agg(
    count("*").alias("count"),
    avg("ip_len").alias("ip_avg_len"),
    avg("frame_len").alias("frame_avg_len"),
    (avg("ip_len") / spark_max("ip_len")).alias("ip_local_anomaly"),
    (avg("frame_len") / spark_max("frame_len")).alias("frame_local_anomaly")
).withColumn("start", col("time_window").getItem("start")).withColumn("end", col("time_window").getItem("end"))

gDf.printSchema()
gDf.show(truncate=False)

# Alias DataFrames to avoid ambiguity
tDf_alias = tDf.alias("tDf")
gDf_alias = gDf.alias("gDf")

# Join tDf and gDf on ip_src, frame_protocols, frame_time (in range of start and end)
cond = (tDf_alias["ip_src"] == gDf_alias["ip_src"]) & \
       (tDf_alias["frame_protocols"] == gDf_alias["frame_protocols"]) & \
       (tDf_alias["frame_time"] >= gDf_alias["start"]) & \
       (tDf_alias["frame_time"] <= gDf_alias["end"])

jDf = tDf_alias.join(gDf_alias, cond, "left").select(
    tDf_alias["ip_src"],
    tDf_alias["ip_dst"],
    tDf_alias["ip_len"],
    tDf_alias["tcp_srcport"],
    tDf_alias["tcp_dstport"],
    tDf_alias["frame_protocols"],
    tDf_alias["frame_len"],
    tDf_alias["frame_time"],
    tDf_alias["timestamp"],
    gDf_alias["ip_avg_len"],
    gDf_alias["frame_avg_len"],
    gDf_alias["ip_local_anomaly"],
    gDf_alias["frame_local_anomaly"],
    gDf_alias["count"]
)

# Show the schema and inspect the data
jDf.printSchema()
jDf.show(truncate=False)

# Add feature column using VectorAssembler
cols = ["ip_avg_len", "frame_avg_len", "ip_local_anomaly", "frame_local_anomaly", "count"]
assembler = VectorAssembler(inputCols=cols, outputCol="features")
fDf = assembler.transform(jDf)

fDf.printSchema()
fDf.show(truncate=False)

# Split dataset into training (70%) and test (30%)
train_data, test_data = fDf.randomSplit([0.7, 0.3], seed=5043)

# Convert to Pandas DataFrame for PyOD
train_pdf = train_data.select("features").toPandas()
test_pdf = test_data.select("features").toPandas()

# Convert 'features' column to numpy array of arrays
X_train = np.array(train_pdf['features'].apply(lambda x: np.array(x.toArray())).tolist())
X_test = np.array(test_pdf['features'].apply(lambda x: np.array(x.toArray())).tolist())

# Flatten into 2D array
X_train_flat = np.array([x.flatten() for x in X_train])
X_test_flat = np.array([x.flatten() for x in X_test])

clf = IForest(
    n_estimators=100,
    bootstrap=False,
    max_samples=256,
    contamination=0.1,
    random_state=1
)

model=clf.fit(X_train_flat)

# Test the model with test dataset
y_test = model.predict(X_test_flat)
y_test_scores = model.decision_function(X_test_flat)

# Create a new data frame with "timestamp", "features", "predicted_label", "outlier_score"
test_pdf["predicted_label"] = y_test
test_pdf["outlier_score"] = y_test_scores
test_pdf["timestamp"] = test_data.select("timestamp").toPandas()
test_pdf["features"] = test_data.select("features").toPandas()

# Save the test data with predicted label and outlier score
test_pdf.to_csv("test_data.csv", index=False)

# Save the model
dump(model, "iforest_model.joblib")