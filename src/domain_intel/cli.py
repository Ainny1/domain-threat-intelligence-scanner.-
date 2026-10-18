"""Command line entry point."""
import argparse
import json
from pathlib import Path
from .core import scan

def main(argv=None):
    parser = argparse.ArgumentParser(description='Low-impact public domain metadata assessment')
    parser.add_argument('domain', help='Domain you own or are authorized to assess')
    parser.add_argument('--timeout', type=float, default=4)
    parser.add_argument('--output', type=Path, help='Save structured JSON report')
    args = parser.parse_args(argv)
    if not 0.5 <= args.timeout <= 20:
        parser.error('Timeout must be between 0.5 and 20 seconds')
    try:
        result = scan(args.domain, args.timeout)
        text = json.dumps(result, indent=2) + '\n'
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(text, encoding='utf-8')
            print(f'Report saved: {args.output}')
        else:
            print(text, end='')
    except ValueError as exc:
        parser.error(str(exc))

if __name__ == '__main__':
    main()
