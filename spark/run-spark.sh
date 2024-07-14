#!/bin/bash

# Construct the --jars argument by listing all JAR files in the directory
JARS=$(echo /opt/spark/jars/*.jar | tr ' ' ',')

sleep 5 # Wait for elasticsearch to start

# Execute the spark-submit command with the dynamically constructed --jars argument
/opt/spark/bin/spark-submit \
  --conf spark.driver.extraJavaOptions="-Divy.cache.dir=/tmp -Divy.home=/tmp" \
  --jars $JARS \
  /opt/spark/work-dir/packet_analyzer.py