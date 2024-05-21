## Start
### First shell
./start.sh 'netowrk-device'
### Second shell
export PYFILE='the python program for spark'
docker-compose up -d

## Stop
### First shell
fg
press ctrl-c
### Second shell
docker-compose down

## Services versions
logstash 8.13.2
zookeper right after 7.6.1
cp-kafka right after 7.6.1
kafka-ui right after 0.7.2
spark-py right after 3.4.0