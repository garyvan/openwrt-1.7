#1 Download pure openWRT source code from gary's github
#echo "Downloading openWRT source code..."
#git clone https://github.com/garyvan/openwrt-1.7.git

#2 Setup the relative path and .config for furthur usage
echo "Setup default .config..."
./redirectpath.sh

#3 Copy feed.tgz and dl.tgz to current place from our server : Z:\public\Sonicwall\Source-Code\openwrt-1.7
cd ./trunk

echo "Copy dl.tgz and feeds.tgz..."
cp /data/public/Sonicwall/Source-Code/openwrt-1.7/used-* .

#4 Untar feed.tgz and dl.tgz
echo "Un-tar dl.tgz and feeds.tgz..."
tar -zxvf used-*dl.tgz 
tar -zxvf used-*feeds.tgz

rm -rf used-*

#5 Install feeds into package
echo "Install all application in feeds to package..."
./scripts/feeds update -a
./scripts/feeds install -a

#6 Install toolchain for Cavium platform.
cp /data/public/Sonicwall/Source-Code/openwrt-1.7/tools.tgz ../OCTEON-SDK
echo "Un-tar and install tools.tgz..."
tar -zxvf ../OCTEON-SDK/tools.tgz -C ../OCTEON-SDK

rm -rf ../OCTEON-SDK/tools.tgz

#7 Use 'make defconfig' to let the system do the rest setting of .config for us
echo "Use "make defconfig" for the rest setting..."
make defconfig

#8 Now the environment setup is complete, we can sumply type 'make' under folder ./trunk to generate the firmware image.
echo "Environment setup finished."
