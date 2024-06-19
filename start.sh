#!/bin/bash
sudo tshark -i ${1} -l -n -x -T ek -a duration:${2} > packets.log
