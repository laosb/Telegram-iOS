"""Brand bundle resource values while preserving keys, URLs and bundle identifiers."""

import argparse
import plistlib
import re
from pathlib import Path


BRAND = re.compile(
    r'(?:https?://|tg://|@)[^\s<>"\])]+|(?<![\w./])'
    r'(?:(?:Telegram|Blah)\s+Premium|Premium|Telegram)(?![\w]|\.[\w])'
)
STRING_ENTRY = re.compile(r'("(?:\\.|[^"\\])*"\s*=\s*")((?:\\.|[^"\\])*)("\s*;)', re.S)


def brand_text(value):
    def replace(match):
        word = match.group()
        if word.startswith('@') or '://' in word:
            return word
        return 'Blah Beyond' if word.endswith('Premium') else 'Blah'

    return BRAND.sub(replace, value)


def brand_plist(value):
    if isinstance(value, dict):
        return {
            key: brand_text(item) if isinstance(item, str) and (
                key in ('CFBundleDisplayName', 'CFBundleName', 'UTTypeDescription')
                or key.endswith('UsageDescription')
            ) else brand_plist(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [brand_plist(item) for item in value]
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    data = args.source.read_bytes()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.source.suffix == '.strings':
        encoding = 'utf-16' if data.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig'
        text = data.decode(encoding)
        args.output.write_text(STRING_ENTRY.sub(
            lambda match: match[1] + brand_text(match[2]) + match[3], text
        ), encoding='utf-8')
    else:
        args.output.write_bytes(plistlib.dumps(brand_plist(plistlib.loads(data)), sort_keys=False))


if __name__ == '__main__':
    main()
