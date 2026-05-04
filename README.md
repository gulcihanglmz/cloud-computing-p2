# Syscall Forensic Analyzer: Docker Intrusion Escape Monitoring

**Container Sentinel** is a security solution designed to detect isolation breaches (**Container Escapes**) and **Privilege Escalation** attempts within Docker environments by analyzing kernel-level system calls (**syscalls**).

## Dataset
The analysis is based on real-world attack traces and container capabilities, publicly available on IEEE Dataport.

**Dataset Link:** [https://ieee-dataport.org/documents/docker-container-escape-attack-dataset-capabilities-and-system-call-traces]
---

## Project Overview
This project introduces a hybrid security architecture that combines **Machine Learning (ML)** with a **Heuristic Rule Engine** to identify complex attack chains that traditional signature-based tools often miss. 

By monitoring syscall patterns in real-time, the system can distinguish between legitimate administrative tasks and malicious attempts to break out of container boundaries.

![alt text](images\sys-flowchart.png)

### Key Features
*   **Hybrid Detection Engine:** Integration of a Multi-Layer Perceptron (MLP) neural network with a deterministic rule-based validator.
*   **Behavioral Vectorization:** Transforms raw syscall logs into numerical vectors based on 7 key metrics: frequency, entropy, dangerous call ratio, privilege ratio, and network activity.
*   **Forensic Reporting:** Identifies specific attack signatures (e.g., `mount` + `unshare` chains) to provide human-readable evidence for SOC analysts.
*   **Risk Suppression:** Intelligent logic that automatically lowers risk scores for baseline behaviors to minimize "alert fatigue."

---

## Performance Benchmarks
The system was evaluated against various architectures, with the **MLP (Neural Network)** model providing the highest fidelity for security operations:

| Model | Accuracy | Precision | Recall | F1-Score |
| :--- | :---: | :---: | :---: | :---: |
| MLP (Neural Net) | 0.9858 | 0.9654 | 0.9993 | 0.9821 |
| Gradient Boosting | 0.9851 | 0.9930 | 0.9684 | 0.9806 |
| Logistic Regression | 0.9449 | 0.8926 | 0.9756 | 0.9322 |
| SVM | 0.7307 | 0.5983 | 0.9328 | 0.7290 |
| Naive Bayes | 0.6621 | 0.5425 | 0.8280 | 0.6556 |

![alt text](images\roc_curve.png)

---

