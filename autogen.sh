#!/bin/sh -e

# Avoid character set dependencies.
unset LC_ALL
export LC_COLLATE=C
export LC_NUMERIC=C

autoreconf --install --symlink
rm --recursive --force autom4te.cache
