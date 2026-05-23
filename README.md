# This is ALU Regex Data Extraction

### How to Run
open you terminal  

gitclone https://github.com/Ntwali-creator/alu-regex-data-extraction_Ntwali-creator.git

cd alu-regex-data-extraction_Ntwali-creator

cd src

python3 main.py


### Extracted Data Types

**  Email addresses (ALU: @alueducation.com, @alumni.alueducation.com, @si.alueducation.com)


** Phone numbers

** Credit card numbers (masked)

## Security Features

Rejects malicious patterns (XSS, SQL injection, command injection)

Masks credit card numbers (only last 4 digits visible)

## Output

Console summary

JSON file: output/sample-output.json
