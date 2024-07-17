#!/bin/bash
count=${2}
while [ $count -gt 0 ]; do
    sudo tshark -i ${1} -l -n -x -T ek -a duration:0.05 >> packets.log
    sleep 1
    count=$((count-1))
done

# sudo tshark -i lo -l -n -x -T ek -a duration:${2} >> packets.log

#this script will run tshark for the specified duration and write the output to packets.log in a single line JSON format
