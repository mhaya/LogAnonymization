# A patch to build wide-tcpdpriv under Linux

original patch:  http://www.ethereal.com/~gerald/tcpdpriv-1.1.10-gerald.patch

http://mawi.wide.ad.jp/mawi/

wget http://mawi.nezu.wide.ad.jp/mawi/tools/tcpd-tools.tar.gz
tar zxvf tcpd-tools.tar.gz
cd tcpd-tools-0.9/wide-tcpdpriv/
patch -b < wide-tcpdpriv-linux.patch
./configure
make

