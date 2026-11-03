"""Restoration job API: the endpoints under /v1/restore and everything behind them.

The package is the API half of the contract in rules/restore-job-protocol.md. It validates a
recipe, takes one video segment in, keeps it in the shared RAM volume, queues it in Redis for the
GPU worker and hands the result back. The worker never sees a key.

Author: Lorenzo Albanese (alblor)
"""
