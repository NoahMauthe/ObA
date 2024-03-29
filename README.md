# Characterizing the Use of Code Obfuscation in Malicious and Benign Android Apps

This is the code repository corresponding to the paper published at ARES 2023.

## Tool capabilities

Our tool was designed to run a large scale analysis on Android apps with regard to code obfuscation techniques.

### Reflection-based obfuscation detection

For this purpose, we implemented a static analysis step using [AndroGuard](https://github.com/androguard/androguard).
This step detects any calls to the Java Reflection API that use non-literal strings as parameters.
We assume that any such calls serve the purpose of obfuscation by hiding the real methods or classes that are dynamically loaded.

### Control-flow obfuscation

Additionally, we implemented a Machine Learning classifier that leverages anomaly detection to discover abnormal control-flow.
The model we used to signify "normal" control-flow was trained on the entire set of applications present in the [F-Droid](https://f-droid.org/) market in 2020, as we assume that Open Source applcations have no need for code obfuscation.
However, you are welcome to train your own model on another (or simply a newer) dataset.
We plan on releasing the code to do so in a timely manner.

## Findings

For results and findings, please refer to our paper "Characterizing the Use of Code Obfuscation in Malicious and Benign Android Apps" published at [ARES 2023](https://www.ares-conference.eu/).

## Requirements

Our entire tool can be run in a containerized fashion.
Thus, in order to execute it, only [Apptainer](https://apptainer.org/) (formerly Singularity) is a requirement with only a few standard Linux applications (e.g. ```curl```, ```touch```, etc.) as install time dependencies.

## Installation

For your convenience we provide a [setup file](scripts/setup.sh) that will perform the installation automatically.
Please note however, that this will simply install the required tools, but not yet set up the database to analyze androzoo applications since this is not necessarily the intnded use case and will downoad GBs of data.

```
mkdir obfuscation_analysis
cd obfuscation_analysis
bash <(curl https://raw.githubusercontent.com/NoahMauthe/ObA/main/scripts/setup.sh)
```

Of course you are also welcome to perform the container based installation manually or instead choose to install the entire toolchain directly to your host.
In the latter case, the tool requires Python3 and the necessary libraries can be found in [analysis.def](environment/analysis.def).

## Database preparation for androzoo analysis

In oder to analyze androzoo apks, you will need to obtain an API key from the team behind it.
However, the follwong step can already be done without this key as it is only required to download apks, not the metadata.

```./analysis createdb androzoo.csv.gz```

The above command will download the current androzoo dataset information (updated daily) and save it to ```androzoo.csv.gz``` for later use.
Additionally, our tool will populate the database with this information so it can be directly used in the next steps of the analysis.

### Virustotal checking

If you also have an API key for virustotal and want to get additional data from that source, the database can be prepared as shown o´below:

```./analysis createdb --sample --local <androzoo.csv.gz> <sample-file>```

In the future, it is the intention to remove this step and instead provide samples for virustotal checking automatically at runtime.

## Attribution

In case you use our tool or finding in your own work, please consider citing our work:

```
@article{Kargn2023CharacterizingTU,
  title={Characterizing the Use of Code Obfuscation in Malicious and Benign Android Apps},
  author={Ulf Karg{\'e}n and Noah Mauthe and Nahid Shahmehri},
  journal={Proceedings of the 18th International Conference on Availability, Reliability and Security},
  year={2023},
}
```
