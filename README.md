# [Argus](https://en.wikipedia.org/wiki/Argus_Panoptes) Benchmark

A (potential) in-house benchmark to asses the strength of LLMs on detecting software vulnerabilities. 

## Quickstart

Running the main.py file proccesses and aggregates all the data

```
python -m src.main
```

the data will be in `src/data/processed`

## Data Sources

Current Data Sources:
1. CleanVul
2. Sven

Looking into:
1. PrimeVul
2. Crawling GitHub and creating an original source dataset (out of scope)


## Citations

```
@inproceedings{sven-llm,
  author       = {Jingxuan He and Martin Vechev},
  title        = {Large Language Models for Code: Security Hardening and Adversarial Testing},
  booktitle    = {ACM CCS},
  year         = {2023},
  url          = {https://arxiv.org/abs/2302.05319},
}
```

```
@article{li2024cleanvul,
  title={CleanVul: Automatic Function-Level Vulnerability Detection in Code Commits Using LLM Heuristics},
  author={Li, Yikun and Zhang, Ting and Widyasari, Ratnadira and Tun, Yan Naing and Nguyen, Huu Hung and Bui, Tan and Irsan, Ivana Clairine and Cheng, Yiran and Lan, Xiang and Ang, Han Wei and others},
  journal={arXiv preprint arXiv:2411.17274},
  year={2024}
}
```

```
@misc{weyssow2025r2vul,
    title={R2VUL: Learning to Reason about Software Vulnerabilities with Reinforcement Learning and Structured Reasoning Distillation},
    author={Martin Weyssow and Chengran Yang and Junkai Chen and Yikun Li and Huihui Huang and Ratnadira Widyasari and Han Wei Ang and Frank Liauw and Eng Lieh Ouh and Lwin Khin Shar and David Lo},
    year={2025},
    eprint={2504.04699},
    archivePrefix={arXiv},
    primaryClass={cs.SE}
}
```