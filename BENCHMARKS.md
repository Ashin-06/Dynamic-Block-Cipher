# Measurements and interpretation

Performance depends on Python version, operating system, CPU, input size, and whether password derivation and permutation-table construction are included. Earlier GPU attack-cost estimates and claimed security strengths were not supported by reproducible measurements and have been removed.

Run these commands from the repository root:

```sh
python --version
python -m unittest discover -v
python demo.py
python avalanche_demo.py --trials 20
```

The demo reports local operation timings. Record your hardware, Python version, revision, data size, and trial count alongside results. Do not extrapolate interactive password-derivation latency to GPU password-guessing rates.

Avalanche charts measure sampled Hamming distances only. They do not establish the Strict Avalanche Criterion for every input/output bit, resistance to cryptanalysis, a security category, or production readiness. The known repeated-output structure in [SECURITY.md](SECURITY.md) persists even when average Hamming distance is near 50%.
