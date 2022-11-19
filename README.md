# CS5340-D01 Fall 2022: Course Project
Group Members:
- Caleb Darnell
- Joshua Ball
- Alec Jamar
- Ravali Chandrapatla 

# Project Overview
- Create a solution that can:
    1) Extract Key Information from files (automatically and without needing to execute them)
    2) Construct an accurate Machine Learning Model that can detect: Benign, Trojan, or Malicious files
    3) Analyze our models to uncover what attributes of a file are indicators that the file is a Trojan attack
    
While the function to parse key information from a file was written by us.

A similar Kaggle competition inspired the attributes we choose to collect:  

    https://www.kaggle.com/competitions/malware-detection/data?select=data.csv
    
The Files we parsed and used for modeling and testing come from the Dike Dataset:

    https://github.com/iosifache/DikeDataset
    

The modeling aspect of the project is created via the Python sklearn library 

The Repo here contains most of what is needed to replicate the project.
To fully replicate the project, you will need to download the entire Dike Dataset from the URL provided above.

### Important Note: The Malicious Files in this repo are REAL! Please Handle with care!