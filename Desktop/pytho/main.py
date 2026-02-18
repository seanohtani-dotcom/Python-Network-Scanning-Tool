import pandas as pd
import numpy as np

# Load the Netflix dataset
df = pd.read_csv("NetflixOriginals.csv")

# Display basic information
print("Dataset Overview:")
print(f"Total rows: {len(df)}")
print(f"Columns: {list(df.columns)}")
print("\nFirst few rows:")
print(df.head())

# Data types
print("\nData Types:")
print(df.dtypes)

# Basic statistics
print("\nBasic Statistics:")
print(df.describe())

# Check for missing values
print("\nMissing Values:")
print(df.isnull().sum())
