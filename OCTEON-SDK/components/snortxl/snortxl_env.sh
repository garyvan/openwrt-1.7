SNORTDIR=$PWD
export PATH=$SNORTDIR/install.linux/bin:$SNORTDIR/install/bin:$PATH
export LD_LIBRARY_PATH=$SNORTDIR/install/lib:$LD_LIBRARY_PATH
mkdir -p /var/log/snort
