# SilentGoby



#### Introduction

This repository is for **SilentGoby**, which contains data and analysis related to vulnerabilities, silent vulnerability fixes, and their collection. It is mainly composed of the following three parts:

1. **Data collection module**

   This module includes the collection of the following vulnerability-related data:

   - CVE vulnerabilities disclosed in the target project
   - Reference information for CVE vulnerabilities, such as disclosure time, severity, and type
   - Vulnerability patches
   - Vulnerability exploits

2. **Data Analysis**

   * Analysis of VEW (Vulnerability Exposure Window) distribution
   * Exploit available time analysis

3. **Dataset**

   * Comprehensive vulnerability information of the target project (`./c`, .`/c++`)
   * Complete vulnerability dataset used in the paper (`formatted_dataset.json`)



#### Code Execution Instructions

The `DataCollection` and `DataAnalysis` folders contain code for data collection and analysis, respectively. You can directly use the `formatted_dataset.json` file in the `Dataset` folder for data analysis.

- **Execution Environment**: The code execution environment is provided by `requirements.txt`.
- **NVD API Setup**: Configure the NVD API to increase the rate limit for vulnerability data collection.
- **Exploit Collection Tools**: Configure local tools for collecting vulnerability exploits by referring to <u>ExploitDB</u> and <u>MetaSploit</u>.
- **Patch Collection Tools**: Configure tools for collecting vulnerability patches by following the setup instructions in the paper *"Enhancing Security in Third-Party Library Reuse – Comprehensive Detection of 1-Day Vulnerability Through Code Patch Analysis"*.
