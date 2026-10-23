#!/bin/sh
set -eu
ollama serve >/tmp/ollama-prepare.log 2>&1 &
task_pid=$!
trap 'kill "$task_pid"' EXIT
sleep 3
ollama pull qwen2.5-coder:7b-instruct-q4_K_M
