# DikeDataset đī¸

## Table of Content đ

- [DikeDataset đī¸](#dikedataset-ī¸)
  - [Table of Content đ](#table-of-content-)
  - [Description đī¸](#description-ī¸)
  - [Labels Exploration đ](#labels-exploration-)
  - [Methodology đˇ](#methodology-)
    - [Downloading Step](#downloading-step)
    - [Renaming Step](#renaming-step)
    - [Scanning Step](#scanning-step)
    - [Labeling Step](#labeling-step)
  - [Sources ÂŠī¸](#sources-ī¸)
  - [Folders Structure đ](#folders-structure-)

## Description đī¸

**DikeDataset** is a **labeled dataset** containing **benign and malicious PE and OLE files**.

Considering the number, the types, and the meanings of the labels, DikeDataset can be used for training artificial intelligence algorithms to predict, for a PE or OLE file, the **malice** and the **membership to a malware family**. The artificial intelligence approaches can vary from machine learning (with algorithms such as regressors and soft multi-label classifiers) to deep learning, depending on the requirements.

It is worth mentioning that the numeric labels, with values between `0` and `1`, can be transformed into discrete ones to respect the constraints of standard classification. For example, if a superior malice limit for benign files is set to `0.4`, a file having the malice of `0.593` is considered malicious.

DikeDataset was proudly used in:
- [`dike`](https://github.com/iosifache/dike), a platform that uses artificial intelligence techniques in the process of malware analysis; and
- ["*Toward Identifying APT Malware through API System Calls*"](https://www.hindawi.com/journals/scn/2021/8077220/), an article about the usage of transfer learning for classifying malware in advanced persistent threat families.

## Labels Exploration đ

<details>
    <summary>Samples Distribution</summary>
    <img src="others/images/distribution.png" alt="Plot with the distribution of samples" width=600>
</details>

<details>
    <summary>Labels Identification</summary>

| Name       | Type    |
| ---------- | ------- |
| type       | int64   |
| hash       | object  |
| malice     | float64 |
| generic    | float64 |
| trojan     | float64 |
| ransomware | float64 |
| worm       | float64 |
| backdoor   | float64 |
| spyware    | float64 |
| rootkit    | float64 |
| encrypter  | float64 |
| downloader | float64 |

</details>

<details>
    <summary>Mean, Standard Deviation, Minimum and Maximum</summary>

|      | malice    | generic   | trojan    | ransomware | worm      | backdoor  | spyware    | rootkit    | encrypter | downloader |
| ---- | --------- | --------- | --------- | ---------- | --------- | --------- | ---------- | ---------- | --------- | ---------- |
| mean | 0.876484  | 0.412354  | 0.44581   | 0.00503229 | 0.0086457 | 0.0117696 | 0.00030322 | 0.00614807 | 0.0719921 | 0.037945   |
| std  | 0.0779914 | 0.0779332 | 0.0891624 | 0.0192288  | 0.0189522 | 0.0333144 | 0.00227205 | 0.0263416  | 0.0622346 | 0.0699552  |
| min  | 0.235294  | 0.140351  | 0.05      | 0          | 0         | 0         | 0          | 0          | 0         | 0          |
| max  | 0.981132  | 0.916667  | 0.76087   | 0.307692   | 0.59      | 0.290323  | 0.0212766  | 0.307692   | 0.3125    | 0.307692   |

</details>

<details>
    <summary>Histograms</summary>
    <img src="others/images/histograms.png" alt="Plot containing a histogram for each numeric label" width=800>
</details>

## Methodology đˇ

> **Observation**: A Bash [script](others/scripts/get_files.sh) can be used to replicate the downloading and the renaming steps. On the other hand, the last two steps consist of using functionalities that are available only in the `dike`, namely in [this](https://github.com/iosifache/dike/blob/main/codebase/scripts/continuous_vt_scan.py) Python script.

### Downloading Step

1. For PE files, a dataset (see the [Sources](#sources-ī¸) section) created for a paper was downloaded. As the files were packed inside multiple folders (one for each malware family considered in the study), they were moved into two new folders, malice oriented.
2. For malicious OLE files, 12 daily (one from each 15th of the 12 previous months) archives were downloaded from MalwareBazaar (see the [Sources](#sources-ī¸) section). After unarchiving, the files were filtered by certain extensions (`.doc`, `.docx` `.docm` `.xls` `.xlsx` `.xlsm` `.ppt` `.pptx` `.pptm`).
3. For benign OLE files, 100 files were manually downloaded from the results of random DuckDuckGo searches.

### Renaming Step

1. All resulting files were renamed by their SHA256 hash.
2. The OLE files, having the Office-specific extensions mentioned in the last paragraph, were replaced with `.ole`.

### Scanning Step

1. The hashes of all malicious files were dumped into a file.
2. The file containing hashes was uploaded into a bucket in Google Cloud Storage.
3. A Google Cloud Function was created, containing a Python script (*see the observation above*) and triggered by a Google Cloud Scheduler four times in a minute (to respect the API quota). It consumed the hashes by scanning them with the VirusTotal API and dumping specific parts of the results (antivirus engines votes and tags) into a [file](others/vt_data.csv).

### Labeling Step

1. The file containing the VirusTotal data, which resulted from the scanning step, was moved locally, where `dike` was already set.
2. To compute the malice, the weighted formula below was used, where the `MALIGN_BENIGN_RATIO` constant was set to `2`. This means that one antivirus engine considering that the file was malicious has the same weight (on a scale) as two engines considering it is benign.

```
malign_weight = MALIGN_BENIGN_RATIO * malign_votes
benign_weight = benign_votes
malice = malign_weight / (malign_weight + benign_weight)
```

3. To compute the membership on each malware family, a transformer was developed (*see the observation above*) to "*vote*" for each available family. For example, if an antivirus engine tag was `Trj`, then one vote for the trojan family was offered. All tags were consumed in this way and the votes for all families were normalized.
4. For the benign files, the process was straight-forward as the malice and the memberships were set to `0`.

## Sources ÂŠī¸

1. [Malware Detection PE-Based Analysis Using Deep Learning Algorithm Dataset](https://figshare.com/articles/dataset/Malware_Detection_PE-Based_Analysis_Using_Deep_Learning_Algorithm_Dataset/6635642), containing malicious and benign PE files and having CC BY 4.0 license
2. [MalwareBazaar](https://bazaar.abuse.ch), containing (among others) malicious OLE files and having CC0 license
3. [DuckDuckGo](https://duckduckgo.com/), that was used for searching benign documents with patterns such as `filetype:doc`

## Folders Structure đ

```
DikeDataset                                 root folder
âââ files                                   folder with all samples
â   âââ benign                              folder for benign samples
â   â   âââ ...
â   âââ malware                             folder for malicious samples
â       âââ ...
âââ labels                                  folder with all labels 
â   âââ benign.csv                          labels folder for benign samples
â   âââ malware.csv                         labels folder for malicious samples
âââ others                                  folder with miscellaneous files
â   âââ images                              folder with generated images
â   â   âââ distribution.png                image with a plot with the distribution of samples
â   â   âââ histograms.png                  image containing the histograms for each numeric label
â   âââ scripts                             folder with used scripts
â   |   âââ explore.py                      Python 3 script for labels exploration
â   |   âââ get_files.sh                    Shell script for downloading a large part of the samples
â   |   âââ requirements.txt                Python 3 dependencies for the explore.py script
â   âââ tables                              folder with generated tables
â   â   âââ labels.md                       table in Markdown format containing the identification 
â   â   â                                   of labels
â   â   âââ univariate_analysis.md          table in Markdown format containing the results of a
â   â                                       univariate analysis
â   âââ vt_data.csv                         raw VirusTotal scan results
âââ README.md                               this file
```