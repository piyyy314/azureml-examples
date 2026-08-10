# Bolt's Performance Optimization Journal

## 2024-12-16 - Prevent Redundant I/O in Build/Generation Scripts
**Learning:** Build and readme/workflow generation scripts (such as `readme.py` in `sdk/python`, `cli`, and `tutorials`) frequently rewrite hundreds of notebook (.ipynb), workflow (.yml), and README (.md) files unconditionally. In a large repository, this causes significant CPU overhead due to JSON/YAML formatting/serialization, and major disk I/O bottlenecks. Making these writes conditional on an actual content change reduces script execution time by ~70% (about 3x faster) and avoids hundreds of unnecessary disk writes.
**Action:** Always check if files (notebooks, generated configs, workflows, and readmes) already have matching content on disk before performing write operations in automation and generation scripts.
