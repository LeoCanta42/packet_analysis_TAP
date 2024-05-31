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
spark custom 3.5.1
elasticsearch 8.13.4
kibana 8.13.4