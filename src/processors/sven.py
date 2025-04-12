import os
import pandas as pd
from tqdm import tqdm
from dotenv import load_dotenv
import anthropic

from ..model import Vulnerability, Span

# Prompt used when no deleted lines exist.
DEFAULT_PROMPT = """
You are a security code analysis expert. Your task is to examine the following code snippet and determine the precise starting and ending line numbers that contain the vulnerability.
Output your answer exactly as follows:

start: <NUMBER>
end: <NUMBER>

No additional commentary or text.
"""

class Sven:
    """
    A processor for analyzing vulnerabilities from a parquet dataset.

    This class loads a parquet file from a dataset (using a specified split),
    iterates over each row to extract vulnerability metadata (code snippet, 
    CWE identifier, vulnerable span, programming language), and aggregates 
    the results as Vulnerability objects.
    """

    def __init__(self, dataset_split: str = 'train', 
                 base_path: str = "hf://datasets/bstee615/sven/",
                 splits: dict = None,
                 api_key: str = None):
        """
        Initialize the processor with a dataset split, file paths, and API credentials.

        Args:
            dataset_split (str, optional): Which split to use ('train' or 'val'). Defaults to 'train'.
            base_path (str, optional): Base path for the dataset. Defaults to "hf://datasets/bstee615/sven/".
            splits (dict, optional): Dictionary mapping split names to file paths.
                Defaults to:
                    {
                        'train': 'data/train-00000-of-00001-23ea0a39e451d835.parquet',
                        'val': 'data/val-00000-of-00001-3175b48e9b496418.parquet'
                    }
            api_key (str, optional): Anthropics API key. If not provided, it is read from the environment variable 'ANTHROPIC_KEY'.
        """
        load_dotenv()
        if splits is None:
            splits = {
                'train': 'data/train-00000-of-00001-23ea0a39e451d835.parquet',
                'val': 'data/val-00000-of-00001-3175b48e9b496418.parquet'
            }
        self.dataset_split = dataset_split
        self.base_path = base_path
        self.splits = splits
        
        self.dataset_file = os.path.join(self.base_path, self.splits[self.dataset_split])
        self.vulnerabilities = []
        
        self.api_key = api_key or os.environ.get("ANTHROPIC_KEY")
        if not self.api_key:
            raise EnvironmentError("ANTHROPIC_KEY not found in environment variables")
        self.client = anthropic.Anthropic(api_key=self.api_key)

    def parse_span_response(self, response_text: str):
        """
        Parse the API response text to extract the start and end line numbers.
        
        Args:
            response_text (str): Raw response text from the API.
        
        Returns:
            tuple: (start (int), end (int))
        """
        start, end = None, None
        lines = response_text.strip().split('\n')
        for line in lines:
            if line.startswith("start:"):
                start = int(line.split(":", 1)[1].strip())
            elif line.startswith("end:"):
                end = int(line.split(":", 1)[1].strip())
        return start, end

    def process_dataset(self):
        """
        Process the parquet dataset file.

        The method reads the parquet file, iterates over its rows, extracts necessary
        fields, computes the span of vulnerable lines (using deleted lines if present or
        prompting the API when absent), determines the programming language, and creates
        Vulnerability objects that are appended to an internal list.
        """
        try:
            df = pd.read_parquet(self.dataset_file)
        except Exception as e:
            raise RuntimeError(f"Error loading dataset from '{self.dataset_file}': {e}")

        for index, row in tqdm(df.iterrows(), total=len(df), desc="Processing dataset"):
            code = row["func_src_before"]
            cwe = row["vul_type"][4:]
            
            deleted_lines = row["line_changes"]["deleted"]
            if len(deleted_lines) == 0:
                response = self.client.messages.create(
                    model="claude-3-7-sonnet-20250219",
                    system=DEFAULT_PROMPT,
                    messages=[{"role": "user", "content": code}],
                    max_tokens=256,
                    temperature=0,
                )
                response_text = response.content[0].text
                start_line, end_line = self.parse_span_response(response_text)
                span = Span(start=start_line, end=end_line)
            elif len(deleted_lines) == 1:
                span = Span(start=deleted_lines[0]["line_no"], end=deleted_lines[0]["line_no"])
            else:
                span = Span(start=deleted_lines[0]["line_no"], end=deleted_lines[-1]["line_no"])
            
            file_name = row["file_name"]
            if ".py" in file_name:
                language = "py"
            elif ".cpp" in file_name:
                language = "cpp"
            elif ".c" in file_name:
                language = "c"
            else:
                language = "unknown"
            
            vuln = Vulnerability(
                code=code,
                cwe=cwe,
                span=span,
                falsePositive=False,
                language=language
            )
            self.vulnerabilities.append(vuln)
        

    def get_vulnerabilities(self):
        """
        Retrieve all processed vulnerabilities.

        Returns:
            list: The aggregated list of Vulnerability objects.
        """
        return self.vulnerabilities

# Example usage:
if __name__ == "__main__":
    processor = SvenProcessor(dataset_split='train')
    processor.process_dataset()
    processed_vulns = processor.get_vulnerabilities()
    
    print(processed_vulns[0])
