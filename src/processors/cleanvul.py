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
        Determine the most appropriate CWE (Common Weakness Enumeration) identifier for the vulnerability.

    Output: Provide the following fields only and nothing else, so that it can be automatically parsed and saved in a database:
        A CWE identifier (e.g., "CWE-79")
        The start line (the first line of the vulnerable code)
        The end line (the last line of the vulnerable code)

Format your answer exactly as:

CWE: <CWE_IDENTIFIER>
start: <NUMBER>
end: <NUMBER>

No additional commentary, no explanation, and no extraneous text.

Remember:

    You must identify the vulnerable lines precisely.
    You must select the correct CWE that most accurately describes the vulnerability.
    Do not include any text other than the three lines specified above in the exact format shown.

Failure to comply with these rules will cause your output to be parsed incorrectly, so ensure absolute adherence.
"""


class CleanVul:
    """
    A processor for analyzing code snippets for vulnerabilities using an external API.
    
    This class:
    1. Scans a given folder for CSV files.
    2. Iterates over each row to extract vulnerability metadata (code snippet, CWE identifier, vulnerable spans, programming language).
    3. Uses an external API to determine the CWE and vulnerable lines.
    4. Creates and stores both the primary and false-positive Vulnerability objects.
    """

    def __init__(self, api_key: str = None, prompt: str = None, data_folder: str = "src/data/raw/CleanVul/"):
        """
        Initialize the processor.

        Args:
            api_key (str, optional): Anthropics API key. If not provided, it is read
                from the environment variable 'ANTHROPIC_KEY'.
            prompt (str, optional): The prompt that will be sent to the API. If not provided,
                the DEFAULT_PROMPT is used.
            data_folder (str, optional): Folder containing CSV files with vulnerability data.
                Defaults to "src/data/raw/CleanVul/".
        """
        load_dotenv()  # Load environment variables
        self.api_key = api_key or os.environ.get("ANTHROPIC_KEY")
        if not self.api_key:
            raise EnvironmentError("ANTHROPIC_KEY not found in environment variables")
        self.client = anthropic.Anthropic(api_key=self.api_key)
        self.prompt = prompt or DEFAULT_PROMPT
        self.data_folder = data_folder
        self.file_paths = self._get_file_paths()
        self.vulnerabilities = []

    def _get_file_paths(self):
        """
        Scan the data folder and return a list of CSV file paths.

        Returns:
            list: List of full CSV file paths from the specified data folder.
        """
        if not os.path.isdir(self.data_folder):
            raise FileNotFoundError(f"Directory '{self.data_folder}' does not exist.")
        
        paths = []
        for filename in os.listdir(self.data_folder):
            if filename.endswith(".csv"):
                full_path = os.path.join(self.data_folder, filename)
                paths.append(full_path)
        return paths

    def parse_span_response(self, response_text: str):
        """
        Parse the API response text to extract the CWE identifier, start line, and end line.

        The response is expected to follow the format:
            CWE: <CWE_IDENTIFIER>
            start: <NUMBER>
            end: <NUMBER>

        Args:
            response_text (str): Raw response text from the API.

        Returns:
            tuple: A tuple (cwe (str), start (int), end (int)).
        """
        cwe, start, end = None, None, None
        lines = response_text.strip().split('\n')
        for line in lines:
            if line.startswith("CWE:"):
                cwe = line.split(":", 1)[1].strip()
            elif line.startswith("start:"):
                start = int(line.split(":", 1)[1].strip())
            elif line.startswith("end:"):
                end = int(line.split(":", 1)[1].strip())
        return cwe, start, end

    def process_file(self, path: str):
        """
        Process a CSV file containing vulnerability code snippets.
        
        For each row in the CSV, this method:
          - Reads the vulnerability information.
          - Calls the API to retrieve the CWE identifier and vulnerable line numbers.
          - Creates a primary Vulnerability object (normal vulnerability) and a false-positive object in separate try/except blocks.

        Args:
            path (str): File path to the CSV file.

        Returns:
            list: A list of Vulnerability objects from the processed file.
        """
        df = pd.read_csv(path)
        local_vulnerabilities = []

        for index, row in tqdm(df.iterrows(), total=len(df), desc=f"Processing {path}"):
            row_dict = row.to_dict()

            try:
                response = self.client.messages.create(
                    model="claude-3-7-sonnet-20250219",
                    system=self.prompt,
                    messages=[{"role": "user", "content": row_dict["func_before"]}],
                    max_tokens=256,
                    temperature=0,
                )
                response_text = response.content[0].text
                cwe, start_line, end_line = self.parse_span_response(response_text)
            except Exception as e:
                print(f"Error during API call/response parsing for row {index} in file '{path}': {e}")
                continue

            try:
                vuln = Vulnerability(
                    code=row_dict["func_before"],
                    cwe=cwe,
                    span=Span(start=start_line, end=end_line),
                    falsePositive=False,
                    language=row_dict["extension"],
                )
                self.vulnerabilities.append(vuln)
            except Exception as e:
                print(f"Error processing normal vulnerability in row {index} in file '{path}': {e}")

            try:
                false_vuln = Vulnerability(
                    code=row_dict["func_after"],
                    cwe=cwe,
                    span=Span(start=start_line, end=end_line),
                    falsePositive=True,
                    language=row_dict["extension"],
                )
                self.vulnerabilities.append(false_vuln)
            except Exception as e:
                print(f"Error processing false vulnerability in row {index} in file '{path}': {e}")

        print(f"Successfully loaded {len(local_vulnerabilities)} vulnerabilities from '{path}'.")
        self.vulnerabilities.extend(local_vulnerabilities)

    def process_dataset(self):
        """
        Process the entire dataset by iterating through all CSV files in the data folder.

        For each CSV file:
          - Reads the file.
          - Processes each vulnerability snippet.
          - Aggregates both the primary and false-positive Vulnerability objects.
        """
        for path in self.file_paths:
            self.process_file(path)

    def get_vulnerabilities(self):
        """
        Retrieve all processed vulnerabilities.
        
        Returns:
            list: Aggregated list of Vulnerability objects.
        """
        return self.vulnerabilities


if __name__ == "__main__":
    clean_vul_processor = CleanVul()
    clean_vul_processor.process_dataset()
    processed_vulns = clean_vul_processor.get_vulnerabilities()
    
    # print("Processed Vulnerabilities:")
    # print(processed_vulns)
