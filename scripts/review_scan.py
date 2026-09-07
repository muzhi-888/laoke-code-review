# -*- coding: utf-8 -*-
"""
代码静态审查扫描器（纯标准库，零依赖）。

作用：把一个目录或单文件喂进来，按"代码审查六维"做一层快速静态体检，
输出结构化报告（Markdown / JSON）。它不替代人审，而是把肉眼最容易漏的
低级红线（硬编码密钥、SQL 拼接、裸 except、eval/exec、弱哈希、调试残留）
先捞出来，让人工 review 把精力放在逻辑与设计上。

用法：
  python review_scan.py <路径> [--format md|json] [--top N] [--max-fn 60] [--max-file 600]

  <路径>  可以是单个 .py/.js/.ts/.jsx/.tsx/.java/.go/.rb/.php 文件，或目录（递归扫描）
  --format  输出格式，默认 md；json 便于接流水线
  --top     只显示前 N 条（按严重度排序），默认全部
  --max-fn  函数体超过多少行算"过长"，默认 60
  --max-file 文件超过多少行算"过大"，默认 600

退出码：始终 0（它是报告器，不是测试门禁；发现问题的多少不影响退出码）。
      若你把它当 CI 门禁用，可自行按 JSON 的严重度字段决定是否 fail。

仅扫描纯文本源码；二进制、node_modules、.git、__pycache__ 自动跳过。
"""
import os
import re
import sys
import ast
import json

# ---------- 规则定义 ----------
SECRET_RE = re.compile(r'(?i)\b(?:password|passwd|pwd|api[_-]?key|apikey|secret|token|access[_-]?key|private[_-]?key|client[_-]?secret|credential|auth)\b\s*[:=]\s*[\'"][^\'"]{6,}[\'"]')
SQL_KEYWORDS = re.compile(r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|MERGE)\b', re.I)
SQL_CONCAT_RE = re.compile(r'(execute\(|cursor\.execute|\.raw\(|query\(|execSql\()', re.I)
EVAL_RE = re.compile(r'\b(eval|exec)\s*\(')
WEAK_HASH_RE = re.compile(r'(hashlib\.(md5|sha1)|\bmd5\(|\bsha1\()')
DEBUG_IMPORT_RE = re.compile(r'^\s*(import\s+(pdb|ipdb)|from\s+(pdb|ipdb)\s+import|breakpoint\s*\()', re.I)
PRINT_RE = re.compile(r'\b(print|console\.log|fmt\.Print(?:ln|f)?|System\.out\.print|echo\s)\b')
TODO_RE = re.compile(r'\b(TODO|FIXME|HACK|XXX|BUG)\b')
MUTABLE_DEFAULT_RE = re.compile(r'def\s+\w+\s*\([^)]*=\s*(\[\]|\{\}|\(\))')

SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}

SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build', '.idea', '.vscode'}
SKIP_EXT = {'.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip', '.gz', '.tar', '.exe',
            '.dll', '.so', '.woff', '.ttf', '.bin', '.pyc', '.lock'}


def collect_files(path):
    files = []
    if os.path.isfile(path):
        files.append(path)
        return files
    for root, dirs, names in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for n in names:
            ext = os.path.splitext(n)[1].lower()
            if ext in SKIP_EXT:
                continue
            files.append(os.path.join(root, n))
    return files


def severity_label(level):
    return level


def scan_python(path):
    findings = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            src = f.read()
    except Exception as e:
        return [{'file': path, 'line': 0, 'sev': 'LOW', 'rule': 'read-error',
                 'msg': f'无法读取文件: {e}', 'fix': '检查文件编码/权限'}]
    lines = src.splitlines()

    # 正则层（全语言通用）
    for i, line in enumerate(lines, 1):
        if SECRET_RE.search(line):
            findings.append({'file': path, 'line': i, 'sev': 'CRITICAL', 'rule': 'hardcoded-secret',
                             'msg': '疑似硬编码密钥/密码/令牌', 'fix': '改从环境变量或密钥管理服务读取，切勿入库'})
        if EVAL_RE.search(line):
            findings.append({'file': path, 'line': i, 'sev': 'HIGH', 'rule': 'eval-exec',
                             'msg': '使用了 eval/exec，存在代码注入风险', 'fix': '用安全的解析/映射替代，禁止执行拼接字符串'})
        if WEAK_HASH_RE.search(line):
            findings.append({'file': path, 'line': i, 'sev': 'HIGH', 'rule': 'weak-hash',
                             'msg': '使用了 MD5/SHA1 等弱哈希', 'fix': '密码用 bcrypt/argon2/scrypt；摘要用 SHA-256 及以上'})
        if MUTABLE_DEFAULT_RE.search(line):
            findings.append({'file': path, 'line': i, 'sev': 'MEDIUM', 'rule': 'mutable-default',
                             'msg': '函数用了可变默认参数([]/{})', 'fix': '改成默认 None，函数内再初始化'})
        if TODO_RE.search(line):
            findings.append({'file': path, 'line': i, 'sev': 'LOW', 'rule': 'todo-marker',
                             'msg': f'遗留标记: {TODO_RE.search(line).group(0)}', 'fix': '确认是否仍需处理，或建 issue 跟进'})
        if DEBUG_IMPORT_RE.search(line):
            findings.append({'file': path, 'line': i, 'sev': 'MEDIUM', 'rule': 'debug-residue',
                             'msg': '调试器/breakpoint 残留', 'fix': '提交前移除 pdb/ipdb/breakpoint'})
        if SQL_CONCAT_RE.search(line) and ('+' in line or '%' in line or '{' in line or 'f"' in line or "f'" in line):
            findings.append({'file': path, 'line': i, 'sev': 'CRITICAL', 'rule': 'sql-injection',
                             'msg': 'SQL 语句疑似字符串拼接（注入风险）', 'fix': '改用参数化查询/占位符，绝不拼接用户输入'})
        if PRINT_RE.search(line):
            findings.append({'file': path, 'line': i, 'sev': 'LOW', 'rule': 'debug-print',
                             'msg': '调试打印语句残留', 'fix': '改用 logging 模块，按级别输出'})

    # AST 层（Python 专属深度分析）
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        findings.append({'file': path, 'line': getattr(e, 'lineno', 0), 'sev': 'MEDIUM',
                         'rule': 'syntax-error', 'msg': f'语法错误: {e}', 'fix': '修复语法后才能正常审查'})
        return findings

    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            if node.type is None:
                findings.append({'file': path, 'line': node.lineno, 'sev': 'HIGH',
                                 'rule': 'bare-except', 'msg': '裸 except: 吞掉所有异常',
                                 'fix': '捕获具体异常类型，至少 except Exception 并做处理'})
            elif isinstance(node.type, ast.Name) and node.type.id == 'Exception':
                # 宽泛捕获仅标记，避免过度噪音
                findings.append({'file': path, 'line': node.lineno, 'sev': 'MEDIUM',
                                 'rule': 'broad-except', 'msg': '捕获过于宽泛的 Exception',
                                 'fix': '细化异常类型；若必须兜底，至少记录日志'})
        if isinstance(node, ast.FunctionDef):
            end = getattr(node, 'end_lineno', node.lineno)
            length = (end - node.lineno) if end else 0
            if length > 0 and length > getattr(scan_python, 'max_fn', 60):
                findings.append({'file': path, 'line': node.lineno, 'sev': 'MEDIUM',
                                 'rule': 'long-function', 'msg': f'函数 {node.name} 过长（{length} 行）',
                                 'fix': '拆分为更小单一职责函数，提升可测性'})
        if isinstance(node, ast.Assert):
            findings.append({'file': path, 'line': node.lineno, 'sev': 'LOW',
                             'rule': 'assert-in-prod', 'msg': '使用了 assert（生产环境 python -O 下会被禁用）',
                             'fix': '参数校验用显式异常，不要依赖 assert'})
    return findings


def scan_generic(path):
    """非 Python 源码：用正则做通用红线扫描。"""
    findings = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        return [{'file': path, 'line': 0, 'sev': 'LOW', 'rule': 'read-error',
                 'msg': f'无法读取: {e}', 'fix': '检查编码/权限'}]
    for i, line in enumerate(lines, 1):
        if SECRET_RE.search(line):
            findings.append({'file': path, 'line': i, 'sev': 'CRITICAL', 'rule': 'hardcoded-secret',
                             'msg': '疑似硬编码密钥/密码/令牌', 'fix': '改从环境变量/密钥管理读取'})
        if EVAL_RE.search(line):
            findings.append({'file': path, 'line': i, 'sev': 'HIGH', 'rule': 'eval-exec',
                             'msg': 'eval/exec 调用（注入风险）', 'fix': '用安全解析/映射替代'})
        if WEAK_HASH_RE.search(line):
            findings.append({'file': path, 'line': i, 'sev': 'HIGH', 'rule': 'weak-hash',
                             'msg': '弱哈希算法', 'fix': '升级到 SHA-256+ 或专用密码哈希'})
        if SQL_CONCAT_RE.search(line) and ('+' in line or '${' in line or 'concat' in line.lower()):
            findings.append({'file': path, 'line': i, 'sev': 'CRITICAL', 'rule': 'sql-injection',
                             'msg': 'SQL 疑似字符串拼接', 'fix': '参数化查询'})
        if TODO_RE.search(line):
            findings.append({'file': path, 'line': i, 'sev': 'LOW', 'rule': 'todo-marker',
                             'msg': f'遗留标记: {TODO_RE.search(line).group(0)}', 'fix': '跟进或建 issue'})
        if PRINT_RE.search(line):
            findings.append({'file': path, 'line': i, 'sev': 'LOW', 'rule': 'debug-print',
                             'msg': '调试打印残留', 'fix': '改用日志框架'})
    return findings


def scan_file(path, max_fn):
    scan_python.max_fn = max_fn
    ext = os.path.splitext(path)[1].lower()
    if ext == '.py':
        return scan_python(path)
    # 文本类源码都走通用扫描
    text_exts = {'.js', '.jsx', '.ts', '.tsx', '.java', '.go', '.rb', '.php', '.cs',
                 '.c', '.cpp', '.h', '.rs', '.swift', '.kt', '.scala', '.sh', '.sql', '.html', '.vue'}
    if ext in text_exts:
        return scan_generic(path)
    # 未知扩展名：尝试当文本通用扫，失败就跳过
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            f.read()
        return scan_generic(path)
    except Exception:
        return []


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 0
    path = args[0]
    fmt = 'md'
    top = 0
    max_fn = 60
    max_file = 600
    i = 1
    while i < len(args):
        a = args[i]
        if a == '--format':
            fmt = args[i + 1]; i += 2
        elif a == '--top':
            top = int(args[i + 1]); i += 2
        elif a == '--max-fn':
            max_fn = int(args[i + 1]); i += 2
        elif a == '--max-file':
            max_file = int(args[i + 1]); i += 2
        else:
            i += 1

    files = collect_files(path)
    if not files:
        print('未发现可扫描的源码文件。')
        return 0

    all_findings = []
    file_line_counts = {}
    for fp in files:
        lc = 0
        try:
            with open(fp, 'r', encoding='utf-8', errors='ignore') as fh:
                lc = sum(1 for _ in fh)
        except Exception:
            pass
        file_line_counts[fp] = lc
        if lc > max_file:
            all_findings.append({'file': fp, 'line': 0, 'sev': 'LOW', 'rule': 'large-file',
                                 'msg': f'文件过大（{lc} 行）', 'fix': '考虑按模块拆分'})
        all_findings.extend(scan_file(fp, max_fn))

    # 按严重度排序
    all_findings.sort(key=lambda x: (SEVERITY_ORDER.get(x['sev'], 9), x['file'], x['line']))
    if top:
        shown = all_findings[:top]
    else:
        shown = all_findings

    counts = {}
    for f in all_findings:
        counts[f['sev']] = counts.get(f['sev'], 0) + 1

    if fmt == 'json':
        out = {'scanned_files': len(files), 'total_lines': sum(file_line_counts.values()),
               'counts': counts, 'findings': shown}
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        print(f'# 代码审查静态扫描报告')
        print()
        print(f'- 扫描文件数：{len(files)}')
        print(f'- 代码总行数：{sum(file_line_counts.values())}')
        print(f'- 发现问题：{len(all_findings)} 条')
        print()
        print('严重度分布：' + '  '.join(f'{k}={counts.get(k,0)}' for k in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] if counts.get(k)))
        print()
        if not shown:
            print('✅ 未命中任何静态红线规则。注意：这不等于代码无问题，仍需人工做逻辑与设计审查。')
        for f in shown:
            loc = f['file'] if not f['line'] else f'{f["file"]}:{f["line"]}'
            print(f'## [{f["sev"]}] {f["rule"]} — {loc}')
            print(f'- 问题：{f["msg"]}')
            print(f'- 建议：{f["fix"]}')
            print()
        print('---')
        print('提示：本报告只覆盖"静态红线"。正确性、可维护性、性能、测试覆盖等需结合本 Skill 的审查清单人工完成。')
    return 0


if __name__ == '__main__':
    sys.exit(main())
