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

A similar Kaggle competition inspired the attributes we chose to collect:  

    https://www.kaggle.com/competitions/malware-detection/data?select=data.csv
    
The Files we parsed and used for modeling and testing come from the Dike Dataset:

    https://github.com/iosifache/DikeDataset
    

The modeling aspect of the project was created via the Python sklearn library 

The Repo here contains most of what is needed to replicate the project.
To fully replicate the project, you will need to download the entire Dike Dataset from the URL provided above.

# Running the Code
- To run the modeling section of the code, you just need to open up the /Code/Modeling/Final Modeling.ipynb file and follow the logic there.
    - While the other files within the Modeling folder were used for exploratory analysis throughout the project's life, the code within the Final Modeling.ipynb is what is discussed within the final paper

- To run the feature extractor code, you need to open up and run the /Code/FeatureExtractor/create_dataset.ipynb
    - Note: You will need to download the Dike Dataset using the link above and point the code to the appropriate files.
    - Additionally, as these are real malware files you might need to turn off or modify anti-virus software to allow the code to extract features from malicious files

### Important Note: The Malicious Files in this Repo are REAL! Please Handle with care!
