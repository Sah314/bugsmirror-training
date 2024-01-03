#!/usr/bin/bash

echo "Today is " `date`
mkdir 'TrainingDay2'
cd TrainingDay2

current_dir=$(pwd)

file_id="1DuAQO7gEQ1iJiM1VWj1Bs4wqsfRsXpP6Ny-leA_d0wc"
output_file="Interns_Training_Programme
.docx"

gdown "https://drive.google.com/uc?id=${file_id}" -O "${output_file}"

echo "Downloaded file successfully at ${current_dir}"