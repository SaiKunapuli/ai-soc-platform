# Notebooks

Exploratory analysis and model evaluation. Suggested sequence (Phase 2):

1. `01_explore_archives.ipynb` — what does a day of Sysmon archive data look like?
2. `02_process_features.ipynb` — build + sanity-check the windowed features
3. `03_isolation_forest_eval.ipynb` — train, score, evaluate against `simulations/labels.csv`

Keep heavyweight data out of git (`data/` is gitignored).
