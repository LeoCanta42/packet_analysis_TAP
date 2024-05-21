## Start

sudo tshark -i 'dev' -l -n -x -T json > packets.log


tested with versions:
logstash 8.13.2
zookeper after 7.6.1
cp-kafka after 7.6.1
kafka-ui after 0.7.2
spark-py after 3.4.0