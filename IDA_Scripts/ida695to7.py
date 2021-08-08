# coding=utf-8

# pylint: disable=C0103,C0111

# Vietnam: Độ chế lại từ nguồn nào đó quên mất tiêu rầu, giờ tìm không ra
#          Còn nhiều bugs, vd parse sai trong strings, comments

from __future__ import print_function

import re
import os
import argparse
import requests

# TODO: add parse and update old IDC functions

# Path of idc_bc695.py file, change according to your IDA location
BC695_FILE = 'Z:/IDA/76/python/2/idc_bc695.py'

# def AskYN(defval, prompt): return ask_yn(defval, prompt)
# Warning=ida_kernwin.warning
DEF_PATTERNS = [re.compile(r'def ([^\(]+)\(.*\): return ([^\(]+)\(.*\)'),
                re.compile(r'(.+)=(.+)')]

IDAPYTHON_DOC_URL = 'https://www.hex-rays.com/products/ida/support/idapython_docs/toc-everything.html'
IDAPYTHON_DOC_HTML = os.path.join(os.path.dirname(__file__), '695_to_7_doc.html')

def main():
    parser = argparse.ArgumentParser(description="IDAPython API name converter")
    parser.add_argument("-o", "--out", action="store", dest="out", help="Specify output file name")
    parser.add_argument("FILE", help="Input IDAPython script")
    args = parser.parse_args()

    if args.out:
        out_file = args.out
    else:
        root, _ext = os.path.splitext(args.FILE)
        out_file = root + "_new.py"

    print('[*] Read {}'.format(BC695_FILE))

    bc695 = []
    with open(BC695_FILE, 'r') as fp:
        for line in fp.readlines():
            line = line.strip('\n')
            for pattern in DEF_PATTERNS:
                m = re.match(pattern, line)
                if m:
                    bc695.append([m.group(1), m.group(2), line])
                    break

    if os.path.exists(IDAPYTHON_DOC_HTML):
        print('[*] Read {}'.format(IDAPYTHON_DOC_HTML))
        with open(IDAPYTHON_DOC_HTML, 'r') as fp:
            text = fp.read()
    else:
        print('[*] Obtain new API name list from {}'.format(IDAPYTHON_DOC_URL))
        response = requests.get(IDAPYTHON_DOC_URL)
        text = response.text
        with open(IDAPYTHON_DOC_HTML, 'w') as fp:
            fp.write(text)

    html_tag_pattern = re.compile(r"<[^>]*?>")
    new_names = sorted(set(html_tag_pattern.sub("", text).split(' ')), reverse=True)

    replace_list = []
    for old, new, line in bc695:
        if new.isdigit() or new.startswith('0x') or len(new.split('.')) == 2:
            replace_list.append([old, new, line])
            continue

        for name in new_names:
            if new in name:
                replace_list.append([old, name, line])
                break

    print('[*] Convert {}'.format(args.FILE))
    with open(args.FILE, 'r') as fp:
        data = fp.read()

    used_modules = []
    flag_modified = False
    for old, new, line in replace_list:
        tmp = re.sub(re.compile(r'([ \n])(idc\.|idaapi\.)*' + old), r'\1' + new, data)
        if data != tmp:
            flag_modified = True
            print(format(line))
            used_modules.append(new.split('.')[0])
            data = tmp

    if flag_modified:
        with open(out_file, 'w') as fp:
            fp.write(data)
        print('[*] Save converted script as {}'.format(out_file))
        print('[*] The script is using the following modules:\n{}'.format(', '.join(set(used_modules))))
    else:
        print('[*] Nothing to do')

if __name__ == "__main__":
    main()
