## Start
- Start the environment by using "docker-compose up -d"
- When everything is started, start capturing with "./capture.sh interface seconds"

## View
View your data in Kibana by accessing localhost:5601 on your browser.
You should import the dashboard and view by:
- Go to "Stack Management" -> "Saved Objects"
- Press on import and select the "KibanaDashboard.ndjson" on kibana_backup

## Testing anomaly
To test an anomaly, execute the "sending_anomaly.py" script while capturing packets on loopback interface (lo)

## Services versions
- logstash 8.13.2
- zookeper right after 7.6.1
- cp-kafka right after 7.6.1
- spark custom 3.5.1
- elasticsearch 8.13.4
- kibana 8.13.4

## Docker Desktop
Resources section for managing memory:
8gb ram, 2gb swap (at least)