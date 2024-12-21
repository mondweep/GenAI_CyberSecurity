# Import necessary libraries
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os
from datetime import datetime
from io import StringIO

# Create results directory if it doesn't exist
results_dir = 'results'
if not os.path.exists(results_dir):
    os.makedirs(results_dir)

# Create a text file for logging results
log_file = os.path.join(results_dir, 'analysis_results.txt')

# Function to log text output
def log_result(text, file=log_file):
    with open(file, 'a') as f:
        f.write(text + '\n')

# Clear previous results
with open(log_file, 'w') as f:
    f.write(f"Analysis Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    f.write("="*50 + "\n\n")

# Read the dataset
df = pd.read_csv('../../input/cyber-security-incidents/incidents.csv')

# 1. Data Preprocessing
missing_values = df.isnull().sum()
log_result("Missing values:\n" + missing_values.to_string())

# Basic information about the dataset - Fixed version
buffer = StringIO()
df.info(buf=buffer)
log_result("\nDataset Info:\n" + "".join(buffer.getvalue().splitlines()))

# 2. Calculate average vulnerability type distribution
vuln_dist = df['Vulnerability Type'].value_counts()
log_result("\nVulnerability Type Distribution:\n" + vuln_dist.to_string())

# 3. Create visualization for vulnerability types
plt.figure(figsize=(12, 6))
sns.barplot(x=vuln_dist.index, y=vuln_dist.values)
plt.xticks(rotation=45)
plt.title('Distribution of Vulnerability Types')
plt.xlabel('Vulnerability Type')
plt.ylabel('Count')
plt.tight_layout()
plt.savefig(os.path.join(results_dir, 'vulnerability_distribution.png'))
plt.close()

# 4. Time-based analysis
df['Timestamp'] = pd.to_datetime(df['Timestamp'])
df['month'] = df['Timestamp'].dt.month
df['year'] = df['Timestamp'].dt.year

monthly_incidents = df.groupby('month')['ID'].count()
plt.figure(figsize=(10, 5))
sns.lineplot(x=monthly_incidents.index, y=monthly_incidents.values)
plt.title('Number of Incidents by Month')
plt.xlabel('Month')
plt.ylabel('Number of Incidents')
plt.savefig(os.path.join(results_dir, 'monthly_incidents.png'))
plt.close()

# 5. Label distribution analysis
label_dist = df['Label'].value_counts()
log_result("\nLabel Distribution:\n" + label_dist.to_string())

# 6. Correlation analysis
correlation_matrix = df.select_dtypes(include=[np.number]).corr()
plt.figure(figsize=(10, 8))
sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm')
plt.title('Correlation Matrix')
plt.tight_layout()
plt.savefig(os.path.join(results_dir, 'correlation_matrix.png'))
plt.close()

# 7. Text length analysis
df['text_length'] = df['Text'].str.len()
plt.figure(figsize=(10, 6))
sns.histplot(data=df, x='text_length', bins=50)
plt.title('Distribution of Text Length')
plt.xlabel('Text Length')
plt.ylabel('Count')
plt.savefig(os.path.join(results_dir, 'text_length_distribution.png'))
plt.close()

# 8. Vulnerability Type vs Label
plt.figure(figsize=(12, 6))
sns.boxplot(data=df, x='Vulnerability Type', y='Label')
plt.xticks(rotation=45)
plt.title('Label Distribution by Vulnerability Type')
plt.tight_layout()
plt.savefig(os.path.join(results_dir, 'vulnerability_vs_label.png'))
plt.close()

# Save summary statistics
summary_stats = df.describe()
log_result("\nSummary Statistics:\n" + summary_stats.to_string())

print(f"Analysis complete. Results saved in {results_dir}/") 