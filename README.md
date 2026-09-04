BranchSherpa: A Fast and Accurate Analytical Modeling Framework for Branch Predictors  
==============

**BranchSherpa** is a fast and accurate analytical modeling framework for branch predictor design exploration.

BranchSherpa improves modeling accuracy over [prior work] through three key techniques.

First, BranchSherpa uses both taken rate and transition rate to derive branch entropy values.
Second, BranchSherpa models multi-component predictors using multiple branch entropy values.
Third, BranchSherpa employs an exponential saturation model to characterize branch predictor behavior.

This repository contains the source code for the BranchSherpa framework and the data required to reproduce the experimental results shown in the paper.
The repository consists of two main components:
1. **Profiling tools** for deriving branch entropy values from target applications. These include an online profiler for instrumenting applications during exeuction and an offline profiler for analyzing pre-collected traces.
2. **Datasets and modeling scripts** for reproducing the analytical modeling workflow. The datasets contain branch entropy and branch miss rate pairs and the scripts are used to fit analytical models of the prior work and BranchSherpa methods.  

[prior work]: https://ieeexplore.ieee.org/document/7095792


## BranchSherpa Framework Setup

### Prerequisites

The framework has been tested on Ubuntu 20.04.5, running on an Intel Xeon Gold 6242R. 
The profiling were conducted using the following configuration:

* `gcc/g++ Version: 11.1.0`
* `Python Version: 3.9.23`
* `Pytorch Version: 2.2.2`
* `CMake Version: 3.16.3`

### Installing DynamoRIO Infrastructure and Building Profiling Tools

To evaluate BranchSherpa, DynamoRIO should first be installed.
DynamoRIO version used in our experiments is no longer publicly available. 
We therefore recommend using version 11.90.20203, the next publicly available version. 
DynamoRIO can be installed using the provided script:

```bash
# Install DynamoRIO
$ ./install_dynamorio.sh
```

Once DynamoRIO has been successfully installed, the profiling tools can be built.
The online profiler can be built using the following:

```bash
# Build online profiler (Please update the path in the script)
$ ./<path/to/online_profiler>/build/build.sh
```

The offline profiler can be built using the following:

```bash
# Build offline profiler (Please update the path in the script)
$ ./<path/to/offline_profiler>/build/build.sh
```

To run the Jupyter notebooks, we recommend using a virtual environment. 
The environment used in our experiments can be created using Conda as follows:

```bash
# Create the conda environment
$ conda create -n branchsherpa python=3.9.23
# Activate the environment
$ conda activate branchsherpa
```

After creating and activating the environment, the required Python packages can be installed as follows:

```bash
# Install the required Python packages
$ pip install -r data/requirements.txt
```

## Modeling Examples

To be updated

## Componenets of the Framework

To be updated

## How to Run Profilers

We provide several example scripts for running profilers provided in this repository.

The classification profiler can be tested using the provided example script:

```bash
# Run the classification profiler (Please modify the script)
$ ./benchmarks/test_classification.sh
```

The baseline entropy profiler tools can be executed as follows:

```bash
# Run the baseline profiler (Please modify the script)
$ ./benchmarks/test_global.sh
```

The BranchSherpa entropy profiler tools can be executed as follows:

```bash
# Run the BranchSherpa profiler (Please modify the script)
$ ./benchmarks/test_tage.sh
```
    
## Citation

If you use our work, please cite our paper:
```
 To appear at IISWC 2026
 ```

## License

This repository is released under the BSD-3-Clause license.
See `LICENSE` for details.
