#! /usr/bin/python

"""Generate files for network performance testing.

The default behavior is to generate 10,000 files all of which are
exactly 3584 bytes long, because that is approximately how big
Flickr's 75x75px JPEG thumbnails are.  You can request a different
size, or you can request that the file sizes instead follow a bounded
Pareto distribution with tunable alpha.

The files have names compatible with httperf's --wset mode.  Since
it insists on .html as a file suffix, the files are syntactically
valid HTML.  Their contents are word salad.

There is one mandatory command line argument: the path to the root
of the tree of files to generate.  It is created if it doesn't
already exist.  If it already exists, its contents will be erased!
(so don't use '.')"""

from __future__ import division

import argparse
import errno
import math
import os
import os.path
import random
import shutil
import sys
import textwrap

def ensure_empty_dir(dpath):
    todelete = []
    try:
        todelete = os.listdir(dpath)
    except OSError, e:
        # Don't delete a _file_ that's in the way.
        # Don't try to create parent directories that are missing.
        if e.errno != errno.ENOENT:
            raise
        os.mkdir(dpath)
        return
    for f in todelete:
        p = os.path.join(dpath, f)
        try:
            os.remove(p)
        except OSError, e:
            if e.errno != errno.EISDIR and e.errno != errno.EPERM:
                raise
            shutil.rmtree(p)

def ensure_parent_directories(path):
    try:
        os.makedirs(os.path.dirname(path))
    except OSError, e:
        if e.errno != errno.EEXIST:
            raise

def word_salad(f, words, seed, maxlen):
    rng = random.Random(seed)
    salad = []
    slen = 0
    while slen < maxlen - 1:
        nl = rng.randint(1, min((maxlen - 1) - slen, len(words))) - 1
        w = rng.choice(words[nl])
        salad.append(w)
        slen += len(w) + 1
    salad = textwrap.fill(" ".join(salad), 78)
    while len(salad) < maxlen-1:
        salad += '.'
    salad += '\n'
    f.write(salad)

def load_words():
    words = [ [] for _ in xrange(15) ]
    for w in open('/usr/share/dict/words'):
        w = w.strip()
        if w.endswith("'s"): continue
        if len(w) > 15 or len(w) < 2: continue
        words[len(w)-1].append(w)
    # special case words[0] as dictfiles often have every single single letter
    words[0].extend(('a','I'))
    return words

FILE_PREFIX = '<!doctype html>\n<title>{0}</title>\n<p>\n'
FILE_SUFFIX = '</p>\n'

def create_one(parent, ctr, digits, words, filesize, seed, resume, progress):
    label = format(ctr, '0'+str(digits)+'d')
    fname = os.path.join(parent, *label) + '.html'
    ensure_parent_directories(fname)

    if os.path.exists(fname):
        if not resume: raise RuntimeError('{0} already exists'.format(fname))
        return

    prefix = FILE_PREFIX.format(label)
    suffix = FILE_SUFFIX
    limit  = filesize - (len(prefix) + len(suffix))
    if limit <= 0:
        raise TypeError("{0} bytes is too small to generate (minimum {1})"
                        .format(filesize, len(prefix)+len(suffix)))

    if progress:
        sys.stderr.write(fname + '\n')

    f = open(fname, "w")
    f.write(prefix)
    word_salad(f, words, ctr+seed, limit)
    f.write(suffix)

def bounded_pareto(rng, alpha, L, H):
    while True:
        U = rng.random()
        if U < 1: break
    Ha = H**alpha
    La = L**alpha
    return int(round((-(U*Ha - U*La - Ha)/(Ha * La)) ** (-1/alpha)))

if __name__ == '__main__':

    default_filesize  = 3584
    default_filecount = 10000  # 0/0/0/0.html through 9/9/9/9.html

    parser = argparse.ArgumentParser(description=__doc__,
                         formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('directory',
                        help='directory to populate with files')
    parser.add_argument('-c', '--count', type=int, default=default_filecount,
                        help='number of files to generate')
    sg = parser.add_mutually_exclusive_group()
    sg.add_argument('-s', '--size', type=int, default=default_filesize,
                    help='all files will be exactly SIZE bytes long')
    sg.add_argument('-p', '--pareto', type=float,
                    metavar='ALPHA',
                    help='file sizes will follow a bounded Pareto distribution'
                    ' with parameter ALPHA')
    parser.add_argument('-m', '--minsize', type=int, default=512,
                        help='minimum file size (only useful with -p)')
    parser.add_argument('-M', '--maxsize', type=int, default=2*1024*1024,
                        help='maximum file size (only useful with -p)')
    parser.add_argument('-S', '--seed', type=int, default=719,
                        help='seed for random number generator')
    parser.add_argument('--resume', action='store_true',
                        help='resume an interrupted run where it left off')
    parser.add_argument('--progress', action='store_true',
                        help='report progress')

    args = parser.parse_args()
    digits = len(str(args.count - 1))
    rng = random.Random(args.seed)

    words = load_words()
    if not args.resume:
        ensure_empty_dir(args.directory)

    size = args.size
    for i in xrange(args.count):
        if args.pareto is not None:
            size = bounded_pareto(rng, args.pareto, args.minsize, args.maxsize)
        create_one(args.directory, i, digits, words, size, args.seed,
                   args.resume, args.progress)
