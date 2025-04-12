import jsonlines
from collections import Counter

import pandas as pd

from src.processors.cleanvul import CleanVul
from src.processors.sven import Sven


def save_vulnerabilities_to_jsonl(vulnerabilities, filename="all_vulnerabilities.jsonl"):
    """
    Save a list of vulnerability objects to a JSONL file using the jsonlines package.

    Each vulnerability is converted to a dictionary. For nested objects (like span),
    we convert them to dictionaries using their __dict__ attribute.
    
    Args:
        vulnerabilities (list): List of Vulnerability objects.
        filename (str): The file name for the JSONL output.
    """
    with jsonlines.open(filename, mode='w') as writer:
        for vuln in vulnerabilities:
            vuln_dict = vuln.__dict__.copy()
            if hasattr(vuln.span, "__dict__"):
                vuln_dict["span"] = vuln.span.__dict__
            writer.write(vuln_dict)


def display_stats(vulnerabilities):
    """
    Display basic statistics about the combined vulnerability dataset.
    
    Prints the distribution of languages and CWE identifiers.
    
    Args:
        vulnerabilities (list): List of Vulnerability objects.
    """
    language_counts = Counter(vuln.language for vuln in vulnerabilities)
    cwe_counts = Counter(vuln.cwe for vuln in vulnerabilities)

    print("Distribution of Languages:")
    for language, count in language_counts.items():
        print(f"  {language}: {count}")

    print("\nDistribution of CWEs:")
    for cwe, count in cwe_counts.items():
        print(f"  {cwe}: {count}")


def main():
    clean_processor = CleanVul()
    clean_processor.process_dataset()  # Processes all CSV files in the configured folder.
    clean_vulns = clean_processor.get_vulnerabilities()
    print(f"CleanVul vulnerabilities: {len(clean_vulns)}")

    sven_processor = Sven(dataset_split='train')
    sven_processor.process_dataset()
    sven_vulns = sven_processor.get_vulnerabilities()
    print(f"Sven vulnerabilities: {len(sven_vulns)}")

    all_vulnerabilities = clean_vulns + sven_vulns
    print(f"Total combined vulnerabilities: {len(all_vulnerabilities)}")

    display_stats(all_vulnerabilities)

    save_vulnerabilities_to_jsonl(all_vulnerabilities, filename="src/data/processed/all_vulnerabilities.jsonl")
    print("Vulnerabilities have been saved to all_vulnerabilities.jsonl")


if __name__ == "__main__":
    main()
