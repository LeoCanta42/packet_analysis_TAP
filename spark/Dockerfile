FROM apache/spark:3.4.2

USER 0
COPY --chown=spark:spark ./libs/* /opt/spark/jars/
COPY --chown=spark:spark ./run-spark.sh /opt/spark/
RUN pip install requests pandas PyArrow elasticsearch geocoder joblib scikit-learn==1.3.2

USER spark
