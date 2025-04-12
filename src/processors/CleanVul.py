import os
import pandas as pd
from tqdm import tqdm
from dotenv import load_dotenv

from ..model import Vulnerability, Span
import anthropic

DEFAULT_PROMPT = """
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

class CleanVul:
    """
    A processor for analyzing code snippets for security vulnerabilities
    using an external API. This class encapsulates reading CSV files, sending
    vulnerable code to the API, parsing the response, and storing the results.
    """

    def __init__(self, api_key: str = None, prompt: str = None):
        """
        Initialize the VulnerabilityProcessor.
        
        Args:
            api_key (str, optional): Anthropics API key. If not provided,
                it is read from the environment variable 'ANTHROPIC_KEY'.
            prompt (str, optional): The prompt to send to the API. Uses DEFAULT_PROMPT
                if not provided.
        """
        load_dotenv()  # Load environment variables

        self.api_key = api_key or os.environ.get("ANTHROPIC_KEY")
        if not self.api_key:
            raise EnvironmentError("ANTHROPIC_KEY not found in environment variables")

        self.client = anthropic.Anthropic(api_key=self.api_key)
        self.prompt = prompt or DEFAULT_PROMPT

        # This list will store all processed Vulnerability objects.
        self.vulnerabilities = []

    def parse_api_response(self, response_text: str):
        """
        Parse the API response text to extract CWEs, start line, and end line.

        Args:
            response_text (str): Raw response text from the API.
        
        Returns:
            tuple: A tuple (cwes, start, end) where:
                - cwes (list of str): The CWE identifiers.
                - start (int): The starting line number.
                - end (int): The ending line number.
        """
        cwes, start, end = None, None, None
        lines = response_text.strip().split('\n')
        for line in lines:
            if line.startswith("CWEs:"):
                # Parse the string inside the brackets into a list.
                cwes_str = line.split(":", 1)[1].strip()
                cwes = [cwe.strip().replace('"', '') for cwe in cwes_str[1:-1].split(',')]
            elif line.startswith("start:"):
                start = int(line.split(":", 1)[1].strip())
            elif line.startswith("end:"):
                end = int(line.split(":", 1)[1].strip())
        return cwes, start, end

    def process_file(self, path: str):
        """
        Process a CSV file containing vulnerability code snippets.
        
        For each row in the CSV, this method:
          - Reads the vulnerability information.
          - Sends the code snippet to the API.
          - Parses the response to extract vulnerable line numbers and CWE identifiers.
          - Creates a Vulnerability object and appends it to the processor's list.
        
        Note: The current logic processes only the first row per file.

        Args:
            path (str): Filepath to the CSV file.
        
        Returns:
            list: A list of Vulnerability objects from the processed file.
        """
        df = pd.read_csv(path)
        local_vulnerabilities = []

        for index, row in tqdm(df.iterrows(), total=len(df), desc=f"Processing {path}"):
            try:
                row_dict = row.to_dict()
                vuln = Vulnerability(
                    code=row_dict["func_before"],
                    cwe=[""],
                    span=Span(start=0, end=int(1e9)),
                    falsePositive=False,
                    language=row_dict["extension"],
                )

                response = self.client.messages.create(
                    model="claude-3-7-sonnet-20250219",
                    system=self.prompt,
                    messages=[{"role": "user", "content": vuln.code}],
                    max_tokens=256,
                    temperature=0,
                )
                response_text = response.content[0].text

                cwes, start_line, end_line = self.parse_api_response(response_text)
                vuln.cwe = cwes
                vuln.span = Span(start=start_line, end=end_line)

                local_vulnerabilities.append(vuln)
            except Exception as e:
                print(f"Error processing row {index} in file '{path}': {e}")
                # Optional: additional error logging can be added here.

            # Process only the first row as per current logic.
            break

        print(f"Successfully loaded {len(local_vulnerabilities)} vulnerabilities from '{path}'.")
        # Append local results to the global list
        self.vulnerabilities.extend(local_vulnerabilities)
        return local_vulnerabilities

    def process_files(self, file_paths: list):
        """
        Process multiple CSV files.
        
        Args:
            file_paths (list): List of file path strings to be processed.
        """
        for path in file_paths:
            self.process_file(path)

    def get_vulnerabilities(self):
        """
        Return all processed vulnerabilities.
        
        Returns:
            list: The aggregated list of Vulnerability objects.
        """
        return self.vulnerabilities


# Example usage:
if __name__ == "__main__":
    # Define the list of CSV files to be processed.
    file_paths = [
        "src/data/CleanVul/CleanVul_vulnscore_3.csv",
        "src/data/CleanVul/CleanVul_vulnscore_4.csv"
    ]
    
    # Instantiate the processor.
    CleanVul = CleanVul()
    
    # Process the given files.
    CleanVul.process_files(file_paths)
    
    # Retrieve and print all processed vulnerabilities.
    processed_vulns = processor.get_vulnerabilities()
    print("Processed Vulnerabilities:")
    print(processed_vulns)
