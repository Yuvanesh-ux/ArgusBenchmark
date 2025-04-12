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
    A processor for analyzing vulnerabilities from a parquet dataset (the Sven dataset).
    
    This class:
    1. Loads the dataset from a specified file path.
    2. Iterates over each row to extract vulnerability metadata (code snippet, 
       CWE identifier, vulnerable spans, programming language).
    3. Uses Anthropics to determine the vulnerable lines if the dataset does not contain 
       “deleted lines”.
    4. Creates and stores Vulnerability objects (both true positives and false positives).
    """

    def __init__(
        self,
        dataset_split: str = 'train',
        splits: dict = None,
        api_key: str = None
    ):
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
            api_key (str, optional): Anthropics API key. If not provided, it is read from the 
                                     environment variable 'ANTHROPIC_KEY'.
        """
        load_dotenv()
        if splits is None:
            splits = {
                'train': 'data/train-00000-of-00001-23ea0a39e451d835.parquet',
                'val': 'data/val-00000-of-00001-3175b48e9b496418.parquet'
            }

        self.dataset_split = dataset_split
        self.base_path = "hf://datasets/bstee615/sven/"
        self.splits = splits
        
        self.dataset_file = os.path.join(self.base_path, self.splits[self.dataset_split])
        self.vulnerabilities = []
        
        # Load API key either from parameter or environment variable
        self.api_key = api_key or os.environ.get("ANTHROPIC_KEY")
        if not self.api_key:
            raise EnvironmentError("ANTHROPIC_KEY not found in environment variables")
        
        # Initialize Anthropics client
        self.client = anthropic.Anthropic(api_key=self.api_key)

    def parse_span_response(self, response_text: str):
        """
        Parse the API response text to extract the start and end line numbers.

        The response format is expected to look like:
            start: <NUMBER>
            end: <NUMBER>

        Args:
            response_text (str): Raw response text from the API.

        Returns:
            tuple: A tuple of (start_line, end_line).
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

        - Reads the parquet file.
        - Iterates over each row to extract necessary fields (code, CWE, etc.).
        - Uses the API to get vulnerable lines if “deleted_lines” is empty.
        - Otherwise uses the existing line numbers in “deleted_lines” to determine the vulnerable span.
        - Identifies the programming language by file name extension.
        - Creates and stores both Vulnerability objects for the real vulnerability (falsePositive=False) 
          and a false-positive example (falsePositive=True).
        """
        try:
            df = pd.read_parquet(self.dataset_file)
        except Exception as exc:
            raise RuntimeError(f"Error loading dataset from '{self.dataset_file}': {exc}")

        for _, row in tqdm(df.iterrows(), total=len(df), desc="Processing Sven dataset"):
            code_before = row["func_src_before"]
            code_after = row["func_src_after"]
            cwe = row["vul_type"][4:]  # Strips 'CWE-' from the front

            # If no deleted lines, ask the model for the vulnerable lines
            deleted_lines = row["line_changes"]["deleted"]
            if len(deleted_lines) == 0:
                response = self.client.messages.create(
                    model="claude-3-7-sonnet-20250219",
                    system=DEFAULT_PROMPT,
                    messages=[{"role": "user", "content": code_before}],
                    max_tokens=256,
                    temperature=0,
                )
                response_text = response.content[0].text
                start_line, end_line = self.parse_span_response(response_text)
                vuln_span = Span(start=start_line, end=end_line)
            elif len(deleted_lines) == 1:
                line_no = deleted_lines[0]["line_no"]
                vuln_span = Span(start=line_no, end=line_no)
            else:
                vuln_span = Span(
                    start=deleted_lines[0]["line_no"],
                    end=deleted_lines[-1]["line_no"]
                )

            # Identify language from file name
            file_name = row["file_name"]
            if file_name.endswith(".py"):
                language = "py"
            elif file_name.endswith(".cpp"):
                language = "cpp"
            elif file_name.endswith(".c"):
                language = "c"
            else:
                language = "unknown"

            # Create the primary Vulnerability object
            vuln = Vulnerability(
                code=code_before,
                cwe=cwe,
                span=vuln_span,
                falsePositive=False,
                language=language
            )

            try:
                # Create a false-positive Vulnerability object
                added_lines = row["line_changes"]["added"]
                if len(added_lines) == 1:
                    line_no = added_lines[0]["line_no"]
                    false_span = Span(start=line_no, end=line_no)
                else:
                    false_span = Span(
                        start=added_lines[0]["line_no"],
                        end=added_lines[-1]["line_no"]
                    )

                false_vuln = Vulnerability(
                    code=code_after,
                    cwe=cwe,
                    span=false_span,
                    falsePositive=True,
                    language=language
                )

                self.vulnerabilities.append(false_vuln)
            except Exception as e:
                print(f"Could not retrieve a False Positive example: {e}")

            # Store both vulnerabilities
            self.vulnerabilities.append(vuln)

    def get_vulnerabilities(self):
        """
        Retrieve all processed vulnerabilities.

        Returns:
            list of Vulnerability: The aggregated list of Vulnerability objects.
        """
        return self.vulnerabilities


if __name__ == "__main__":
    processor = Sven(dataset_split='train')
    processor.process_dataset()
    processed_vulns = processor.get_vulnerabilities()
    
    print(processed_vulns[0])
