# Import necessary libraries
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# Read the dataset
df = pd.read_csv('../../input/cyber-security-incidents/incidents.csv')

# 1. Data Preprocessing
# Check for missing values
print("Missing values:\n", df.isnull().sum())

# Basic information about the dataset
print("\nDataset Info:")
print(df.info())

# 2. Calculate average vulnerability type distribution
vuln_dist = df['Vulnerability Type'].value_counts()
print("\nVulnerability Type Distribution:")
print(vuln_dist)

# 3. Create visualization for vulnerability types
plt.figure(figsize=(12, 6))
sns.barplot(x=vuln_dist.index, y=vuln_dist.values)
plt.xticks(rotation=45)
plt.title('Distribution of Vulnerability Types')
plt.xlabel('Vulnerability Type')
plt.ylabel('Count')
plt.tight_layout()
plt.show()

# 4. Time-based analysis
df['Timestamp'] = pd.to_datetime(df['Timestamp'])
df['month'] = df['Timestamp'].dt.month
df['year'] = df['Timestamp'].dt.year

# Monthly trend
monthly_incidents = df.groupby('month')['ID'].count()

plt.figure(figsize=(10, 5))
sns.lineplot(x=monthly_incidents.index, y=monthly_incidents.values)
plt.title('Number of Incidents by Month')
plt.xlabel('Month')
plt.ylabel('Number of Incidents')
plt.show()

# 5. Label distribution analysis
label_dist = df['Label'].value_counts()
print("\nLabel Distribution:")
print(label_dist)

# 6. Correlation analysis
correlation_matrix = df.select_dtypes(include=[np.number]).corr()
plt.figure(figsize=(10, 8))
sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm')
plt.title('Correlation Matrix')
plt.tight_layout()
plt.show()

# 7. Text length analysis
df['text_length'] = df['Text'].str.len()
plt.figure(figsize=(10, 6))
sns.histplot(data=df, x='text_length', bins=50)
plt.title('Distribution of Text Length')
plt.xlabel('Text Length')
plt.ylabel('Count')
plt.show()

# 8. Vulnerability Type vs Label
plt.figure(figsize=(12, 6))
sns.boxplot(data=df, x='Vulnerability Type', y='Label')
plt.xticks(rotation=45)
plt.title('Label Distribution by Vulnerability Type')
plt.tight_layout()
plt.show() 