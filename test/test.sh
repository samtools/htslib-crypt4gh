#!/bin/sh

# Find htsfile

echo -n "Looking for htsfile (HTSDIR=$HTSDIR) ... " 1>&2

HTSFILE='no'
if [ -x $HTSDIR/bin/htsfile ] ; then
    HTSFILE=$HTSDIR/bin/htsfile
else if [ -x $HTSDIR/htsfile ] ; then
	 HTSFILE=$HTSDIR/htsfile
     fi
fi

if [ $HTSFILE = "no" ] ; then
    echo "Couldn't find htsfile" 1>&2
    exit 1
else
    echo "$HTSFILE" 1>&2
fi

# Set path to find plugin

HTS_PATH=plugin
export HTS_PATH

# Round trip test

"$HTSFILE" -C test/ce#1.sam crypt4gh:test/ce#1.tmp.encrypted.sam && \
"$HTSFILE" -C crypt4gh:test/ce#1.tmp.encrypted.sam test/ce#1.tmp.sam && \
cmp test/ce#1.sam test/ce#1.tmp.sam

if [ $? -ne 0 ] ; then
    echo "Failed: Round trip test" 1>&2
    exit 1
fi

echo "Passed"
exit 0
