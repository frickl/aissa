"""Offline labeled evaluation. Expected labels are never sent to the model."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

from . import analyzer


def load_cases(manifest, group='all'):
    root = manifest.resolve().parent
    value = json.loads(manifest.read_text())
    if not isinstance(value, dict) or not isinstance(value.get('cases'), list):
        raise ValueError('Invalid evaluation manifest')
    cases, seen = [], set()
    for item in value['cases']:
        if (not isinstance(item, dict) or not isinstance(item.get('id'), str)
                or not item['id'] or item['id'] in seen
                or item.get('expected') not in analyzer.CLASSES
                or item.get('group') not in ('regression', 'new')
                or not isinstance(item.get('file'), str)):
            raise ValueError('Invalid evaluation case')
        seen.add(item['id'])
        path = (root/item['file']).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError('Invalid evaluation path')
        if group == 'all' or item['group'] == group:
            cases.append(dict(item, path=path))
    if not cases:
        raise ValueError('Empty evaluation selection')
    return cases


def evaluate(cases, model, timeout, emit):
    matrix = {label: Counter() for label in analyzer.CLASSES}
    correct = errors = ham_total = ham_bad = live_timely = 0
    for case in cases:
        expected = case['expected']
        row = dict(event='case', id=case['id'], group=case['group'], expected=expected)
        if expected == 'ham':
            ham_total += 1
        try:
            with case['path'].open('rb') as handle:
                verdict = analyzer.classify(handle.read(analyzer.MAX_MAIL+1), model, timeout)
            predicted = verdict['classification']
            row.update(status='ok', predicted=predicted, correct=predicted == expected,
                       confidence=verdict['confidence'], reason=verdict['reason'],
                       elapsed_seconds=verdict['elapsed_seconds'])
            correct += predicted == expected
            ham_bad += expected == 'ham' and predicted in ('spam', 'phishing')
            live_timely += verdict['elapsed_seconds'] < 10
        except Exception as exc:
            predicted = 'error'
            errors += 1
            row.update(status='error', predicted='error', correct=False,
                       error_type=type(exc).__name__)
        matrix[expected][predicted] += 1
        emit(row)
    summary = dict(event='summary', total=len(cases), correct=correct,
                   mismatches=len(cases)-correct-errors, errors=errors,
                   ham_total=ham_total, ham_labeled_spam_or_phishing=ham_bad,
                   backend_under_10_seconds=live_timely,
                   confusion_matrix={label: dict(counts) for label, counts in matrix.items()})
    emit(summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--group', choices=['all','regression','new'], default='all')
    parser.add_argument('--model', default='qwen2.5:1.5b')
    parser.add_argument('--timeout', type=float, default=60)
    parser.add_argument('--prompt', choices=['current','previous'], default='current')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if not 0 < args.timeout <= 300:
        parser.error('timeout must be >0 and <=300 seconds')
    try:
        cases = load_cases(args.manifest, args.group)
        system = analyzer.SYSTEM
        if args.prompt == 'previous':
            system = (args.manifest.resolve().parent/'previous_prompt.txt').read_text()
        if args.output and (args.output.resolve() == args.manifest.resolve()
                            or any(args.output.resolve() == c['path'] for c in cases)
                            or args.output.resolve() == args.manifest.resolve().parent/'previous_prompt.txt'):
            parser.error('Output must not overwrite evaluation inputs')
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    out = args.output.open('w') if args.output else sys.stdout
    def emit(value):
        print(json.dumps(value, ensure_ascii=False), file=out, flush=True)
    old = analyzer.SYSTEM
    analyzer.SYSTEM = system
    try:
        emit(dict(event='run', model=args.model, group=args.group, prompt=args.prompt,
                  prompt_sha256=hashlib.sha256(system.encode()).hexdigest(),
                  prompt_characters=len(system), timeout=args.timeout,
                  note='Synthetic development set; labels withheld from inference.'))
        summary = evaluate(cases, args.model, args.timeout, emit)
    finally:
        analyzer.SYSTEM = old
        if out is not sys.stdout:
            out.close()
    return int(summary['errors'] > 0)


if __name__ == '__main__':
    raise SystemExit(main())
