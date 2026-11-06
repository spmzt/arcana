#!/usr/bin/env python3
#
# The console's RESTCONF, module by module, as Markdown: the modules
# the console serves of its own (its YANG library, restconf.c's
# library_object()) and those each host's agent serves below the fleet
# mount (share/mk/arcana.yang.mk's ARC_YMODS of an agent's build), each
# with its top-level data nodes, rpcs, actions and notifications as
# RFC 8040 api-paths, read from share/yang.  The book's "RESTCONF
# paths, by module" is this script's output, made at every build of it.
#
#	python3 -I docs/restconf-modules.py [arcana-top] > restconf-paths.md
#
# A YANG reader of its own, no libyang: statements, imports, includes,
# groupings (uses expanded where they are used, nodes in the using
# module's namespace), augments applied across modules.  Features,
# when and deviations are not applied: a path is the module's, the
# library says what a host has on.

import os
import re
import sys

TOP = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                      os.path.join(os.path.dirname(__file__), '..'))
YDIR = os.path.join(TOP, 'share', 'yang')
H = '/restconf/data/arcana-fleet:fleet/host=<id>'


# --- Statements --------------------------------------------------------

class Stmt:
    __slots__ = ('kw', 'arg', 'subs')

    def __init__(self, kw, arg):
        self.kw, self.arg, self.subs = kw, arg, []

    def all(self, kw):
        return [s for s in self.subs if s.kw == kw]

    def one(self, kw):
        for s in self.subs:
            if s.kw == kw:
                return s.arg
        return None


def tokens(text):
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif text.startswith('//', i):
            i = text.find('\n', i)
            i = n if i < 0 else i
        elif text.startswith('/*', i):
            i = text.find('*/', i) + 2
        elif c in ';{}':
            yield c
            i += 1
        elif c in '"\'':
            # Quoted, perhaps concatenated with +.
            s = ''
            while True:
                q = text[i]
                j = i + 1
                if q == "'":
                    k = text.index("'", j)
                    s += text[j:k]
                else:
                    buf = []
                    k = j
                    while text[k] != '"':
                        if text[k] == '\\':
                            k += 1
                            buf.append({'n': '\n', 't': '\t'}.get(
                                text[k], text[k]))
                        else:
                            buf.append(text[k])
                        k += 1
                    s += ''.join(buf)
                i = k + 1
                m = re.compile(r'\s*\+\s*').match(text, i)
                if m and i < n and m.end() < n and text[m.end()] in '"\'':
                    i = m.end()
                    continue
                break
            yield ('s', s)
        else:
            m = re.compile(r'[^\s;{}"\']+').match(text, i)
            yield ('s', m.group(0))
            i = m.end()


def parse(text):
    stack = [Stmt(None, None)]
    toks = list(tokens(text))
    i = 0
    while i < len(toks):
        t = toks[i]
        if t == '}':
            stack.pop()
            i += 1
            continue
        kw = t[1]
        arg = None
        i += 1
        if toks[i] not in (';', '{'):
            arg = toks[i][1]
            i += 1
        s = Stmt(kw, arg)
        stack[-1].subs.append(s)
        if toks[i] == '{':
            stack.append(s)
        i += 1
    return stack[0].subs[0]


# --- Modules -----------------------------------------------------------

_files = {}


def yang_file(name, rev=None):
    if rev:
        p = os.path.join(YDIR, '%s@%s.yang' % (name, rev))
        if os.path.exists(p):
            return p
    if not _files:
        for f in os.listdir(YDIR):
            if f.endswith('.yang'):
                n = f[:-5].split('@')[0]
                _files.setdefault(n, []).append(f)
    fs = sorted(_files.get(name, []))
    return os.path.join(YDIR, fs[-1]) if fs else None


class Module:
    def __init__(self, name, rev=None):
        path = yang_file(name, rev)
        if path is None:
            raise FileNotFoundError(name)
        with open(path, encoding='utf-8') as f:
            st = parse(f.read())
        self.name = name
        self.rev = os.path.basename(path)[:-5].partition('@')[2]
        self.stmt = st
        self.prefix = st.one('prefix')
        self.ns = st.one('namespace')
        self.prefixes = {self.prefix: name}
        for imp in st.all('import'):
            self.prefixes[imp.one('prefix')] = imp.arg
        self.body = list(st.subs)
        for inc in st.all('include'):
            sub = parse(open(yang_file(inc.arg, inc.one('revision-date')),
                             encoding='utf-8').read())
            for imp in sub.all('import'):
                self.prefixes.setdefault(imp.one('prefix'), imp.arg)
            self.body += sub.subs
        self.groupings = {}

        def collect(stmts):
            for s in stmts:
                if s.kw == 'grouping':
                    self.groupings.setdefault(s.arg, s)
                collect(s.subs)
        collect(self.body)
        d = st.one('description') or ''
        self.description = ' '.join(d.split())

    def resolve(self, qname):
        p, _, n = qname.rpartition(':')
        return (self.prefixes.get(p, p) if p else self.name), n


_mods = {}


def module(name, rev=None):
    if name not in _mods:
        _mods[name] = Module(name, rev)
    return _mods[name]


# --- The schema tree -----------------------------------------------------

DATA = ('container', 'list', 'leaf', 'leaf-list', 'anydata', 'anyxml',
        'choice', 'case', 'action', 'notification', 'input', 'output')


class Node:
    __slots__ = ('kw', 'name', 'mod', 'keys', 'kids')

    def __init__(self, kw, name, mod, keys):
        self.kw, self.name, self.mod, self.keys = kw, name, mod, keys
        self.kids = []

    def child(self, mod, name):
        for k in self.kids:
            if k.name == name and k.mod == mod:
                return k
        return None


def implicit_io(n):
    """An action's or rpc's input and output, there if not written."""
    for io in ('input', 'output'):
        if n.child(n.mod, io) is None:
            n.kids.append(Node(io, io, n.mod, []))


def expand(stmts, ctx, ns, into, depth=0):
    """Make Nodes of stmts (read in module ctx's prefixes) in namespace
    ns, appended to into."""
    if depth > 40:
        return
    for s in stmts:
        if s.kw == 'uses':
            gm, gn = ctx.resolve(s.arg)
            try:
                g = module(gm).groupings.get(gn)
            except FileNotFoundError:
                g = None
            if g is not None:
                expand(g.subs, module(gm), ns, into, depth + 1)
        elif s.kw in DATA:
            kw = s.kw
            if kw in ('input', 'output'):
                name = kw
            else:
                name = s.arg
            k = s.one('key')
            n = Node(kw, name, ns, k.split() if k else [])
            into.append(n)
            expand(s.subs, ctx, ns, n.kids, depth + 1)
            if kw == 'action':
                implicit_io(n)
        elif s.kw in ('augment',) and depth > 0:
            pass    # a uses' augment: not applied


class Schema:
    def __init__(self, names):
        self.top = Node('root', '', '', [])
        self.augmented = {}         # module -> [(target path, Node)]
        pending = []
        for name in names:
            m = module(name)
            tops = [s for s in m.body if s.kw != 'augment' and
                    (s.kw in DATA or s.kw in ('uses', 'rpc'))]
            for s in tops:
                if s.kw == 'rpc':
                    n = Node('rpc', s.arg, m.name, [])
                    self.top.kids.append(n)
                    expand(s.subs, m, m.name, n.kids)
                    implicit_io(n)
                else:
                    expand([s], m, m.name, self.top.kids)
            for a in m.body:
                if a.kw == 'augment':
                    pending.append((m, a))
        # Augments of augments: until none applies.
        while pending:
            left = []
            for m, a in pending:
                t = self.find(m, a.arg)
                if t is None:
                    left.append((m, a))
                    continue
                kids = []
                expand(a.subs, m, m.name, kids)
                t.kids += kids
                self.augmented.setdefault(m.name, []).append((t, kids))
            if len(left) == len(pending):
                for m, a in left:
                    print('restconf-modules: %s: augment %s: no target' %
                          (m.name, a.arg), file=sys.stderr)
                break
            pending = left
        self.parent = {}

        def link(n):
            for k in n.kids:
                self.parent[id(k)] = n
                link(k)
        link(self.top)

    def find(self, m, target):
        n = self.top
        for step in target.strip().strip('/').split('/'):
            mod, name = m.resolve(step)
            n = n.child(mod, name)
            if n is None:
                return None
        return n

    def path(self, n):
        segs = []
        while n is not self.top:
            segs.append(n)
            n = self.parent[id(n)]
        out, mod = [], None
        for s in reversed(segs):
            if s.kw in ('choice', 'case', 'input', 'output'):
                continue
            seg = s.name if s.mod == mod else '%s:%s' % (s.mod, s.name)
            mod = s.mod
            if s.kw == 'list' and s.keys:
                seg += '=' + ','.join('<%s>' % k for k in s.keys)
            out.append(seg)
        return '/'.join(out)

    def walk(self, n=None):
        n = n or self.top
        for k in n.kids:
            yield k
            yield from self.walk(k)


# --- The two libraries ---------------------------------------------------

def make_vars(path, console):
    """ARC_YMODS and ARC_YIMPORTS of arcana.yang.mk, as an agent's build
    (console False) or the console's has them."""
    out = {'ARC_YMODS': [], 'ARC_YIMPORTS': []}
    text = open(path, encoding='utf-8').read().replace('\\\n', ' ')
    on = [True]
    for line in text.splitlines():
        line = line.split('#', 1)[0] if not line.startswith('.') else line
        m = re.match(r'\.if\s+\$\{ARC_YANG_CONSOLE:Uno\}\s*(==|!=)\s*"yes"',
                     line)
        if m:
            on.append(on[-1] and ((m.group(1) == '==') == console))
            continue
        if line.startswith('.if'):
            on.append(on[-1])
            continue
        if line.startswith('.endif'):
            on.pop()
            continue
        m = re.match(r'(ARC_YMODS|ARC_YIMPORTS)\s*(\+?=)\s*(.*)', line)
        if m and on[-1]:
            words = m.group(3).split()
            if m.group(2) == '=':
                out[m.group(1)] = words
            else:
                out[m.group(1)] += words
    return out


def console_library(path):
    """restconf.c's library_object(): its mods[] and imps[]."""
    text = open(path, encoding='utf-8').read()
    body = text[text.index('library_object(void)'):]
    body = body[:body.index('\n}\n')]
    mods = body[body.index('mods[]'):body.index('imps[]')]
    imps = body[body.index('imps[]'):]
    entry = re.compile(r'\{\s*"([a-z0-9-]+)",\s*"([0-9-]+)"')
    return entry.findall(mods), entry.findall(imps[:imps.index('};')])


# --- Markdown -------------------------------------------------------------

def sources():
    out = {}
    try:
        for line in open(os.path.join(YDIR, 'README.md'), encoding='utf-8'):
            m = re.match(r'\|\s*`([a-z0-9-]+)@[0-9-]+\.yang`\s*\|[^|]*\|'
                         r'\s*([^|]*)\|', line)
            if m:
                src = m.group(2).strip()
                src = re.sub(r'\s*\(YangModels/yang[^)]*\)', '', src)
                out[m.group(1)] = src.split(';')[0].strip()
    except OSError:
        pass
    return out


def first_sentence(text):
    m = re.match(r'(.+?[.:])(\s|$)', text)
    return (m.group(1) if m else text).rstrip(':.') + '.' if text else ''


def mod_rows(schema, names, base, ops):
    """For each module: (top-level nodes, rpcs, actions, notifications,
    augmented targets)."""
    rows = {}
    for name in names:
        rows[name] = {'data': [], 'rpc': [], 'action': [], 'notif': [],
                      'aug': []}
    for n in schema.top.kids:
        r = rows.get(n.mod)
        if r is None:
            continue
        if n.kw in ('container', 'list', 'leaf', 'leaf-list', 'anydata'):
            r['data'].append(base + '/' + schema.path(n))
        elif n.kw == 'rpc':
            r['rpc'].append(ops + n.mod + ':' + n.name)
        elif n.kw == 'notification':
            r['notif'].append(n.mod + ':' + n.name)
    for n in schema.walk():
        r = rows.get(n.mod)
        if r is None:
            continue
        if n.kw == 'action':
            r['action'].append(base + '/' + schema.path(n))
        elif n.kw == 'notification' and schema.parent[id(n)] is not \
                schema.top:
            r['notif'].append(schema.path(n))
    for name in names:
        for t, kids in schema.augmented.get(name, []):
            if t.kw == 'rpc' or any(k.kw in ('input', 'output')
                                    for k in [t]):
                continue
            p = schema.path(t)
            if p and (base + '/' + p) not in rows[name]['aug']:
                rows[name]['aug'].append(base + '/' + p)
    return rows


def short(paths, base):
    return ', '.join('`%s`' % p[len(base) + 1:] if p.startswith(base + '/')
                     else '`%s`' % p for p in paths)


def section(out, title, names, revs, rows, base, src, about):
    out += ['## ' + title, '', about, '',
            '| Module | Revision | From | Top-level data | rpcs | actions |',
            '|---|---|---|---|---|---|']
    for name in names:
        r = rows[name]
        out.append('| [`%s`](#%s) | %s | %s | %s | %d | %d |' % (
            name, anchor(title, name), revs[name],
            'Arcana' if name.startswith('arcana') else src.get(name, ''),
            short(r['data'], base) or '—', len(r['rpc']), len(r['action'])))
    out.append('')


def anchor(title, name):
    return ('c-' if title.startswith('The console') else 'h-') + name


def details(out, title, names, rows, base, mods):
    for name in names:
        r, m = rows[name], mods[name]
        out += ['<a id="%s"></a>' % anchor(title, name), '',
                '#### `%s@%s`' % (name, m.rev), '']
        if name.startswith('arcana') and m.description:
            out += [first_sentence(m.description), '']
        out += ['Namespace `%s`, prefix `%s`.' % (m.ns, m.prefix), '']
        for key, label in (('data', 'Data'), ('aug', 'Augments'),
                           ('rpc', 'rpcs (POST)'),
                           ('action', 'Actions (POST)'),
                           ('notif', 'Notifications')):
            if r[key]:
                out.append('- %s:' % label)
                out += ['  - `%s`' % (p.replace(H, 'H', 1)
                                      if p.startswith(H) else p)
                        for p in r[key]]
        if not any(r.values()):
            out.append('- Types, identities or groupings alone.')
        out.append('')


def main():
    src = sources()
    agent = make_vars(os.path.join(TOP, 'share', 'mk', 'arcana.yang.mk'),
                      False)
    cmods, cimps = console_library(os.path.join(
        TOP, 'www', 'arcana-console', 'restconf.c'))
    hnames = [m.split('@')[0] for m in agent['ARC_YMODS']]
    hrevs = {m.split('@')[0]: m.split('@')[1] for m in agent['ARC_YMODS']}
    cnames = [n for n, _ in cmods]
    crevs = dict(cmods)
    for n, r in cmods + [(m.split('@')[0], m.split('@')[1])
                         for m in agent['ARC_YMODS']]:
        module(n, r)

    hs = Schema(hnames)
    cs = Schema(cnames)
    hrows = mod_rows(hs, hnames, H, H + '/')
    crows = mod_rows(cs, cnames, '/restconf/data', '/restconf/operations/')

    out = ['# RESTCONF paths, by module', '',
           '*Generated from Arcana\'s `share/yang`, the console\'s YANG '
           'library (`www/arcana-console/restconf.c`) and an agent\'s '
           '(`share/mk/arcana.yang.mk`) by `docs/restconf-modules.py` at '
           'every build of the book.*', '',
           'Every module the console serves, and every module an agent '
           'of this release serves below the fleet mount, with its '
           'top-level data nodes, its rpcs, its actions and its '
           'notifications as RFC 8040 api-paths. `H` is a host\'s entry, '
           '`%s`; a list entry is named by its keys, `=<key>`. Features '
           'are not applied: a host\'s own `ietf-yang-library` says '
           'which it has on. See [The API: RESTCONF]'
           '(../automation/restconf.md) for how each is used.' % H, '']
    section(out, 'The console\'s own', cnames, crevs, crows,
            '/restconf/data', src,
            'Its `ietf-yang-library` at `/restconf/data/'
            'ietf-yang-library:yang-library`, one module set and one '
            'schema; paths are below `/restconf/data`, its rpcs at '
            '`/restconf/operations/<module>:<rpc>`. Imported alone, for '
            'their types and identities: %s.' % ', '.join(
                '`%s@%s`' % (n, r) for n, r in cimps))
    section(out, 'Each host\'s', hnames, hrevs, hrows, H, src,
            'An agent\'s `ietf-yang-library`, read at `H/ietf-yang-'
            'library:yang-library`; paths are below `H` (or a datastore\'s '
            '`/restconf/ds/ietf-datastores:<name>/arcana-fleet:fleet/'
            'host=<id>`), its rpcs POSTed at `H/<module>:<rpc>`. An agent '
            'of another release serves its own set: its library is the '
            'one to trust. Imported alone: %s.' % ', '.join(
                '`%s`' % m for m in agent['ARC_YIMPORTS']))
    out += ['## Module by module', '', '### The console\'s own', '']
    details(out, 'The console\'s own', cnames, crows, '/restconf/data',
            _mods)
    out += ['### Each host\'s', '']
    details(out, 'Each host\'s', hnames, hrows, H, _mods)
    sys.stdout.write('\n'.join(out) + '\n')


if __name__ == '__main__':
    main()
