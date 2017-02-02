# tcpdpriv-1.2 linux support patch

http://ita.ee.lbl.gov/html/contrib/tcpdpriv.html

original patch: http://www.ethereal.com/~gerald/tcpdpriv-1.1.10-gerald.patch

CentOS 7.3

sudo yum install nettools 
wget ftp://ita.ee.lbl.gov/software/tcpdpriv-1.2.tar.gz
tar zxvf tcpdpriv-1.2.tar.gz
cd tcpdpriv-1.2
patch -b < tcpdpriv-1.2-linux.patch
./configure
make



