#!/bin/bash
sudo tshark -i ${1} -l -n -x -T json > packets.log
