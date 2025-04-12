import pandas as pd
from tqdm import tqdm
import os
from ..model import Vulnerability, Span
import anthropic
import json
from dotenv import load_dotenv

load_dotenv()

api_key = os.environ.get("ANTHROPIC_KEY")
client = anthropic.Anthropic(api_key=api_key)
prompt = """
You are a security code analysis expert. You have one and only one task:
    Input: You are given a snippet of code that is confirmed to contain a vulnerability.
    Process:
        Read and interpret the code snippet.
        Identify the specific lines of code that cause the vulnerability.
        Determine the most appropriate CWE (Common Weakness Enumeration) identifier(s) for the vulnerability.

    Output: Provide the following fields only and nothing else, so that it can be automatically parsed and saved in a database:
        An array of CWE identifiers (e.g., ["CWE-79"] or ["CWE-79","CWE-89"])
        The start line (the first line of the vulnerable code)
        The end line (the last line of the vulnerable code)

Format your answer exactly as:

CWEs: [<CWE_IDENTIFIER_1>, <CWE_IDENTIFIER_2>, ...]
start: <NUMBER>
end: <NUMBER>

No additional commentary, no explanation, and no extraneous text.

Remember:

    You must identify the vulnerable lines precisely.
    You must select the correct CWE(s) that most accurately describe the vulnerability.
    Do not include any text other than the three lines specified above in the exact format shown.

Failure to comply with these rules will cause your output to be parsed incorrectly, so ensure absolute adherence.
"""
    
vulnerabilities = []

def processor(path):
    df = pd.read_csv(path)

    for index, row in tqdm(df.iterrows()):
        try:
            row = row.to_dict()

            vuln = Vulnerability(
                code=row["func_before"],
                cwe=[""],
                span=Span(start=0, end=1e9),
                falsePositive=False,
                language=row["extension"],
            )

            resp = client.messages.create(
                model="claude-3-7-sonnet-20250219",  
                system=prompt,  
                messages=[
                    {"role": "user", "content": vuln.code}  
                ],
                max_tokens=256,  
                temperature=0,  
            )

            response_text = resp.content[0].text
            lines = response_text.strip().split('\n')

            cwes = None
            start = None
            end = None

            for line in lines:
                if line.startswith("CWEs:"):
                    cwes_str = line.split(":")[1].strip()
                    # Remove the brackets and quotes to get a list of CWEs
                    cwes = [cwe.strip().replace('"', '') for cwe in cwes_str[1:-1].split(',')]
                elif line.startswith("start:"):
                    start = int(line.split(":")[1].strip())
                elif line.startswith("end:"):
                    end = int(line.split(":")[1].strip())

            vuln.cwe = cwes
            vuln.span = Span(start=start, end=end)
            # print(vuln.language)
            vulnerabilities.append(vuln)
        except Exception as e:
            print(f"Error validating row {index}: {e}")
            # print(f"Row data: {row.to_dict()}")
    
        break

    print(f"Successfully loaded {len(vulnerabilities)} vulnerabilities.")
    return vulnerabilities

if __name__ == "__main__":
    file_paths = ["src/data/CleanVul/CleanVul_vulnscore_3.csv", "src/data/CleanVul/CleanVul_vulnscore_4.csv"]

    processed_vulnerabilities = []
    for path in file_paths:
        processed_vulnerabilities.extend(processor(path))
    
    print(processed_vulnerabilities)


