#!/usr/bin/env bash
# Run several configs for several agent models; models run in parallel, configs in order.
#
#   adversarial_tests/tool_guard_eval/run_matrix.sh \
#       --configs "none hybrid_d3" --models "qwen-3.8-27b gemma-4-31b-it" -- --split dev
#
# Everything after "--" is passed to run_evaluation. Logs: results/logs/<tag>_<model>.log
set -euo pipefail

cd "$(dirname "$0")/../.."
configs="none hybrid_d3"
models="qwen-3.8-27b"
tag="run"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --configs) configs="$2"; shift 2 ;;
    --models) models="$2"; shift 2 ;;
    --tag) tag="$2"; shift 2 ;;
    --) shift; break ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done

if [[ -f .env ]]; then set -a; source .env; set +a; fi
python="${PYTHON:-.venv/bin/python}"
logs=adversarial_tests/tool_guard_eval/results/logs
mkdir -p "$logs"

for model in $models; do
  (
    for config in $configs; do
      "$python" -m adversarial_tests.tool_guard_eval.run_evaluation --config "$config" --model "$model" "$@"
    done
  ) > "$logs/${tag}_${model}.log" 2>&1 &
done
wait
echo "finished: configs=[$configs] models=[$models]"
