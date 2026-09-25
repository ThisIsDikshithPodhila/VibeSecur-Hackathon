#!/usr/bin/env python3
"""Run real repair/verification gates. Blocked is exit 2, never a passing gate."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from vibesecur.repair import RepairExecutor
from verifier.runner import verify, contract_digest


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['repair','verify','contract'],default='contract')
    parser.add_argument('--config',type=Path)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if args.mode=='contract':
        print(json.dumps({'verificationContractDigest':contract_digest(),'runtimeStatus':'not_run'}))
        return 0
    if not args.config:
        parser.error('--config is required for real execution')
    config=json.loads(args.config.read_text())
    if args.mode=='verify':
        result=verify(config)
    else:
        executor=RepairExecutor(config['runtime'])
        result=executor.start(config['mission'],lambda event: print(json.dumps(event),flush=True))
    encoded=json.dumps(result,indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_text(encoded)
    print(encoded)
    return 0 if result.get('passed') or result.get('state')=='candidate' else (2 if result.get('state')=='blocked' else 1)


if __name__=='__main__':
    raise SystemExit(main())
