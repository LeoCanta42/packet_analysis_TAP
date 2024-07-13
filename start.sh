#!/bin/bash
sudo tshark -i ${1} -i lo -l -n -x -T ek -a duration:${2} >> packets.log
# sudo tshark -i lo -l -n -x -T ek -a duration:${2} >> packets.log

#this script will run tshark for the specified duration and write the output to packets.log in a single line JSON format