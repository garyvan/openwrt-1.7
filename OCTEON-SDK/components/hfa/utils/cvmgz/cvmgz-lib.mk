obj-y += ../../utils/cvmgz/cvmgz-lib.o
EXTRA_CFLAGS += -I$(OCTEON_ROOT)/linux/kernel/linux/include/linux 
../../utils/cvmgz/cvmgz-lib-objs :=					  \
		../../utils/cvmgz/adler32.o                   \
		../../utils/cvmgz/crc32.o                     \
		../../utils/cvmgz/deflate.o                   \
		../../utils/cvmgz/infback.o                   \
		../../utils/cvmgz/inffast.o                   \
		../../utils/cvmgz/inflate.o                   \
		../../utils/cvmgz/inftrees.o                  \
		../../utils/cvmgz/trees.o                     \
		../../utils/cvmgz/zutil.o                     \
		../../utils/cvmgz/compress.o                  \
		../../utils/cvmgz/uncompr.o                   \
		../../utils/cvmgz/gzclose.o                   \
		../../utils/cvmgz/gzlib.o                     \
		../../utils/cvmgz/gzread.o                    \
		../../utils/cvmgz/gzwrite.o                   \
		../../utils/cvmgz/misc_defs.o
