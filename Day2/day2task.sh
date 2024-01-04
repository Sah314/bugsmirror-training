#!/usr/bin/bash
mkdir 'TrainingDay2'
cd TrainingDay2

current_dir=$(pwd)

file_id="1s6_apLYJFt1tMkhmlJX5Lbd2t45pXvc2Vc04bmFLXmg"
output_file="Sahil_Task2.docx"

gdown "https://drive.google.com/uc?id=${file_id}" -O "${output_file}"

echo "Downloaded file successfully at ${current_dir}"

hostname=$(whoami)
cpuinfo=$(lscpu)
num_cores=$(echo "$cpuinfo" | grep -E '^CPU\(s\):' | awk '{print $2}')
architecture=$(echo "$cpuinfo" | grep 'Architecture' | awk '{print $2}')
total_ram=$(grep -m1 'MemTotal' /proc/meminfo | awk '{print $2}')
available_ram=$(grep -m1 'MemAvailable' /proc/meminfo | awk '{print $2}')
storageinfo=$(df -h)

echo -e "Hostname: $hostname\nNo. of Cores: $num_cores\nArchitecture: $architecture\nTotal RAM:$total_ram kB\nAvailable RAM: $available_ram kB\n$storageinfo" > systeminfo.txt
