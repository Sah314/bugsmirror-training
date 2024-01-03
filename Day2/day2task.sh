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
raminfo=$(free -m)
storageinfo=$(df)

echo ${hostname}"\n"${cpuinfo}"\n"${raminfo}"\n"${storageinfo} > systeminfo.txt
