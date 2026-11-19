# Paper

The course paper (ACM `sigconf`, 5 pages + references and appendix).

```bash
pip install -e '.[workspace,paper]'
python -m paper.make_tables     # every table and in-text number, from adversarial_tests/tool_guard_eval/results/
python -m paper.make_figures    # Figure 2 (figures/off_vs_on.pdf)
cd paper && tectonic main.tex   # or latexmk -pdf main.tex
```

- `main.tex`, `sections/*.tex`, `refs.bib`: the paper. Figure 1 is TikZ in `sections/app.tex`.
- `generated/`: written by `make_tables.py` (`numbers.tex` holds every number used in the text as a
  macro). Don't edit by hand.
- `REVIEW_LOG.md`: the independent review rounds and what changed after each.

The runs behind each results file, with their exact commands, are in
`adversarial_tests/tool_guard_eval/EXPERIMENTS.md` (E5–E17); the paper's appendix maps each table
to its runs.
