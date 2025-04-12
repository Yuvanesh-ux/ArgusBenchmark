import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
from src.processors.cleanvul import CleanVul
from src.processors.sven import Sven

def main():
    # Process CleanVul vulnerabilities.
    # cleanvul_processor = CleanVul()
    # cleanvul_processor.process_all_files()
    # clean_vulns = cleanvul_processor.get_vulnerabilities()

    # Process Sven vulnerabilities.
    sven_processor = Sven(dataset_split='train')
    sven_processor.process_dataset()
    sven_vulns = sven_processor.get_vulnerabilities()

    sven_processor = Sven(dataset_split='val')
    sven_processor.process_dataset()
    sven_vulns += sven_processor.get_vulnerabilities()

    # Combine the vulnerabilities from both sources.
    # all_vulnerabilities = clean_vulns + sven_vulns
    all_vulnerabilities = sven_vulns

    print(f"Total Vulnerabilities Processed: {len(all_vulnerabilities)}")

    # Calculate distributions of languages and CWEs.
    language_counts = Counter(vuln.language for vuln in all_vulnerabilities)
    cwe_counts = Counter(vuln.cwe for vuln in all_vulnerabilities)

    # Convert the distributions into pandas DataFrames for a nice display.
    language_df = pd.DataFrame(language_counts.items(), columns=['Language', 'Count'])
    cwe_df = pd.DataFrame(cwe_counts.items(), columns=['CWE', 'Count'])

    # Display the DataFrames.
    print("\nDistribution of Languages:")
    print(language_df)
    print("\nDistribution of CWEs:")
    print(cwe_df)

if __name__ == "__main__":
    main()
