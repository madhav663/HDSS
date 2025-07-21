# # # import pandas as pd
# # # import matplotlib.pyplot as plt
# # # import seaborn as sns
# # # import numpy as np

# # # # Load the benchmark CSV file
# # # df = pd.read_csv('HAPQS_proof_report.csv')

# # # # Normalize column names if needed
# # # df.columns = [c.strip() for c in df.columns]

# # # # -- Add Signature Length (bytes), if only hex is present
# # # if 'Signature' in df.columns and 'SigSize' not in df.columns:
# # #     df['SigSize'] = df['Signature'].str.len() // 2  # Hex string to bytes

# # # # ==== 1. ADDITIONAL CHARTS/METRICS ====

# # # print("==== Per-Scheme Descriptive Stats ====")
# # # desc = df.groupby('Scheme').agg({
# # #     'SignTimeNs': ['mean', 'median', 'min', 'max', 'std'],
# # #     'VerifyTimeNs': ['mean', 'median', 'min', 'max', 'std'],
# # #     'SigSize': ['mean', 'median', 'min', 'max', 'std'],
# # #     'Valid': 'mean',
# # #     'TamperedValid': 'mean'
# # # })
# # # print(desc)

# # # # Table: Scheme ranking by average sign time
# # # sign_rank = desc['SignTimeNs']['mean'].sort_values()
# # # print("\nFastest Schemes (Signing) in order:")
# # # print(sign_rank)

# # # # Table: Scheme ranking by average verify time
# # # verify_rank = desc['VerifyTimeNs']['mean'].sort_values()
# # # print("\nFastest Schemes (Verification) in order:")
# # # print(verify_rank)

# # # # Table: Scheme ranking by average signature size
# # # size_rank = desc['SigSize']['mean'].sort_values()
# # # print("\nSmallest Signature Schemes in order:")
# # # print(size_rank)

# # # # ==== 2. BOXPLOTS & HISTOGRAMS ====

# # # plt.figure(figsize=(12,6))
# # # sns.boxplot(x='Scheme', y='SignTimeNs', data=df)
# # # plt.title("Signature Generation Time Distribution")
# # # plt.ylabel("Sign Time (ns)")
# # # plt.xlabel("Scheme")
# # # plt.yscale('log')
# # # plt.show()

# # # plt.figure(figsize=(12,6))
# # # sns.boxplot(x='Scheme', y='VerifyTimeNs', data=df)
# # # plt.title("Verification Time Distribution")
# # # plt.ylabel("Verify Time (ns)")
# # # plt.xlabel("Scheme")
# # # plt.yscale('log')
# # # plt.show()

# # # plt.figure(figsize=(12,6))
# # # sns.boxplot(x='Scheme', y='SigSize', data=df)
# # # plt.title("Signature Size Distribution")
# # # plt.ylabel("Signature Size (bytes)")
# # # plt.xlabel("Scheme")
# # # plt.show()

# # # # Histogram: All sign times
# # # plt.figure(figsize=(12,6))
# # # for scheme in df['Scheme'].unique():
# # #     subset = df[df['Scheme'] == scheme]
# # #     plt.hist(subset['SignTimeNs'], bins=30, alpha=0.4, label=scheme)
# # # plt.title('Histogram of Signature Generation Times')
# # # plt.xlabel('Sign Time (ns)')
# # # plt.ylabel('Count')
# # # plt.legend()
# # # plt.xscale('log')
# # # plt.show()

# # # # Histogram: All verify times
# # # plt.figure(figsize=(12,6))
# # # for scheme in df['Scheme'].unique():
# # #     subset = df[df['Scheme'] == scheme]
# # #     plt.hist(subset['VerifyTimeNs'], bins=30, alpha=0.4, label=scheme)
# # # plt.title('Histogram of Verification Times')
# # # plt.xlabel('Verify Time (ns)')
# # # plt.ylabel('Count')
# # # plt.legend()
# # # plt.xscale('log')
# # # plt.show()

# # # # Histogram: Signature size
# # # plt.figure(figsize=(12,6))
# # # for scheme in df['Scheme'].unique():
# # #     subset = df[df['Scheme'] == scheme]
# # #     plt.hist(subset['SigSize'], bins=30, alpha=0.4, label=scheme)
# # # plt.title('Histogram of Signature Size')
# # # plt.xlabel('Signature Size (bytes)')
# # # plt.ylabel('Count')
# # # plt.legend()
# # # plt.show()

# # # # ==== 3. TABLE: PER-ROW SIGNATURE SUCCESS/FAIL ====
# # # failures = df[df['Valid'] == False]
# # # print(f"\nTotal signature failures: {len(failures)} (out of {len(df)})")

# # # # Table for the first 10 signature "proofs"
# # # print("\nSample Signature Proof Table:")
# # # print(df[['Row', 'Scheme', 'Message', 'Signature', 'Valid', 'TamperedValid']].head(10).to_string())

# # # # Pie Chart: Valid vs Invalid for all schemes combined
# # # valid_counts = df['Valid'].value_counts()
# # # plt.figure(figsize=(6, 6))
# # # plt.pie(valid_counts, labels=['Valid', 'Invalid'], autopct='%1.1f%%', colors=['#8fd9b6', '#ff9999'])
# # # plt.title("Signature Validity Distribution (All Schemes)")
# # # plt.savefig('signature_validity_pie.png')
# # # plt.show()

# # # # Area Chart: Cumulative Sign Time per Scheme
# # # df['CumulativeSign'] = df.groupby('Scheme')['SignTimeNs'].cumsum()
# # # for scheme in df['Scheme'].unique():
# # #     plt.plot(df[df['Scheme']==scheme]['Row'], df[df['Scheme']==scheme]['CumulativeSign'], label=scheme)
# # # plt.title('Cumulative Signature Time per Scheme')
# # # plt.xlabel('Row (Message #)')
# # # plt.ylabel('Cumulative Sign Time (ns)')
# # # plt.legend()
# # # plt.savefig('cumulative_sign_time.png')
# # # plt.show()
# # import pandas as pd
# # import matplotlib.pyplot as plt

# # df = pd.read_csv('HAPQS_proof_report.csv')

# # # Pie Chart: Valid vs Invalid for all schemes combined
# # valid_counts = df['Valid'].value_counts()
# # plt.figure(figsize=(6, 6))
# # plt.pie(valid_counts, labels=['Valid', 'Invalid'], autopct='%1.1f%%', colors=['#8fd9b6', '#ff9999'])
# # plt.title("Signature Validity Distribution (All Schemes)")
# # plt.savefig('signature_validity_pie.png')
# # plt.show()

# # # Area Chart: Cumulative Sign Time per Scheme
# # df['CumulativeSign'] = df.groupby('Scheme')['SignTimeNs'].cumsum()
# # for scheme in df['Scheme'].unique():
# #     plt.plot(df[df['Scheme']==scheme]['Row'], df[df['Scheme']==scheme]['CumulativeSign'], label=scheme)
# # plt.title('Cumulative Signature Time per Scheme')
# # plt.xlabel('Row (Message #)')
# # plt.ylabel('Cumulative Sign Time (ns)')
# # plt.legend()
# # plt.savefig('cumulative_sign_time.png')
# # plt.show()

# import pandas as pd
# import matplotlib.pyplot as plt

# df = pd.read_csv('HAPQS_proof_report.csv')

# # Robustly count valid/invalid
# valid_counts = df['Valid'].value_counts().to_dict()
# labels = []
# sizes = []
# colors = []

# # Add both classes (even if zero for one)
# if True in valid_counts or 'True' in valid_counts or 1 in valid_counts:
#     valid = valid_counts.get(True, 0) + valid_counts.get('True', 0) + valid_counts.get(1, 0)
# else:
#     valid = 0

# if False in valid_counts or 'False' in valid_counts or 0 in valid_counts:
#     invalid = valid_counts.get(False, 0) + valid_counts.get('False', 0) + valid_counts.get(0, 0)
# else:
#     invalid = 0

# labels = []
# sizes = []
# colors = []
# if valid > 0:
#     labels.append("Valid")
#     sizes.append(valid)
#     colors.append("#8fd9b6")
# if invalid > 0:
#     labels.append("Invalid")
#     sizes.append(invalid)
#     colors.append("#ff9999")

# plt.figure(figsize=(6, 6))
# plt.pie(sizes, labels=labels, autopct='%1.1f%%', colors=colors)
# plt.title("Signature Validity Distribution (All Schemes)")
# plt.show()

import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv('HAPQS_proof_report.csv')

# Bar chart: Tampered valid rate (should be low for good schemes)
scheme_groups = df.groupby('Scheme')
tampered_valid = scheme_groups['TamperedValid'].mean()

plt.bar(tampered_valid.index, tampered_valid.values)
plt.ylabel('Fraction Tampered Valid (Should be 0)')
plt.title('Tampered Signature Acceptance Rate (Lower is Better)')
plt.show()
