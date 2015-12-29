# Define the paths, pwd should be the root path that is ./openwrt-1.7
workPath=`pwd`
openwrtPath=$workPath/trunk
octeonsdkPath=$workPath/OCTEON-SDK
kernelPath=$octeonsdkPath/linux/kernel/linux/
toolchainPath=$octeonsdkPath/tools
config="cavm_cn71xx_toolchain"

cd $openwrtPath
# Copy the delta .config used for cn71xx platform from ./trunk/config/cn71xx-default.config
echo "Copying $config config"
cp $openwrtPath/config/$config .config

# Modify some paths in .config as the current ones.

sed  "s/CONFIG_EXTERNAL_KERNEL_TREE=.*//g" -i $openwrtPath/.config
# Insert a newline to ensure kernel tree config is written on a new line
echo "" >> $openwrtPath/.config
echo CONFIG_EXTERNAL_KERNEL_TREE=\"$kernelPath\" >> $openwrtPath/.config

if [ -e "$toolchainPath" ]
then
    sed  "s/CONFIG_TOOLCHAIN_ROOT=.*//g" -i $openwrtPath/.config
    sed  "s/CONFIG_LIBC_ROOT_DIR=.*//g" -i $openwrtPath/.config
    sed  "s/CONFIG_LIBGCC_ROOT_DIR=.*//g" -i $openwrtPath/.config
    sed  "s/CONFIG_LIBPTHREAD_ROOT_DIR=.*//g" -i $openwrtPath/.config
    sed  "s/CONFIG_LIBRT_ROOT_DIR=.*//g" -i $openwrtPath/.config
    sed  "s/CONFIG_LIBSTDCPP_ROOT_DIR=.*//g" -i $openwrtPath/.config
    sed  "s/CONFIG_LIBSSP_ROOT_DIR=.*//g" -i $openwrtPath/.config

    # Insert a newline to ensure config is written on a new line
    echo "" >> $openwrtPath/.config

    echo CONFIG_TOOLCHAIN_ROOT=\"$toolchainPath\" >> $openwrtPath/.config
    echo CONFIG_LIBC_ROOT_DIR=\"$toolchainPath\" >> $openwrtPath/.config
    echo CONFIG_LIBGCC_ROOT_DIR=\"$toolchainPath\" >> $openwrtPath/.config
    echo CONFIG_LIBPTHREAD_ROOT_DIR=\"$toolchainPath\" >> $openwrtPath/.config
    echo CONFIG_LIBRT_ROOT_DIR=\"$toolchainPath\" >> $openwrtPath/.config
    echo CONFIG_LIBSTDCPP_ROOT_DIR=\"$toolchainPath\" >> $openwrtPath/.config
    echo CONFIG_LIBSSP_ROOT_DIR=\"$toolchainPath\" >> $openwrtPath/.config
fi

