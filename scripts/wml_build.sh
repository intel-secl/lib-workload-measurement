CUR_DIR="$(dirname "$(readlink -f ${BASH_SOURCE[0]})")"
echo $CUR_DIR
LOG_FILE=$CUR_DIR/outfile
arg1=$1

##################################################################################
# check the flavour of OS
function which_flavour()
{
        flavour=""
        grep -c -i ubuntu /etc/*-release > /dev/null
        if [ $? -eq 0 ]; then
                flavour="ubuntu"
        fi
        grep -c -i "red hat" /etc/*-release > /dev/null
        if [ $? -eq 0 ]; then
                flavour="rhel"
        fi
        grep -c -i fedora /etc/*-release > /dev/null
        if [ $? -eq 0 ]; then
                flavour="fedora"
        fi
        grep -c -i SuSE /etc/*-release > /dev/null
        if [ $? -eq 0 ]; then
                flavour="suse"
        fi
		grep -c -i centos /etc/*-release > /dev/null
        if [ $? -eq 0 ]; then
                flavour="centos"
        fi
        if [ "$flavour" == "" ]; then
                echo "Unsupported linux flavor, Supported versions are ubuntu, rhel, fedora, centos and suse"
                exit 1
        else
                echo $flavour
        fi
}

function install_pkg()
{
	os_flavour=`which_flavour`
	echo "installing required packages $os_flavour ..."
	if [ $os_flavour == "ubuntu" ]
	then
		sudo -n apt-get update
		sudo -n apt-get install --force-yes -y make gcc g++ libxml2-dev libssl-dev "linux-headers-`uname -r`" dos2unix
	elif [ $os_flavour == "rhel" ] || [ $os_flavour == "fedora" ] || [ $os_flavour == "centos" ]
	then
		sudo -n yum install -y make libgcc gcc-c++ libxml2-devel openssl-devel "kernel-devel-uname-r == $(uname -r)" dos2unix
	elif [ $os_flavour == "suse" ]
	then
		sudo -n zypper -n in make gcc gcc-c++ libxml2-devel libopenssl-devel kernel-desktop-devel dos2unix
	fi
}

function help_display()
{
	echo "Usage: ./wml_build.sh [Options] "
	echo ""
	echo "1. Builds the measure binary"
	echo "2. Builds the wml library"
	echo ""
	echo "Options available : "
	echo "--help"
	echo "--installpkg-only"
}

function buildwml()
{
    cd $CUR_DIR/../src

    echo > $LOG_FILE
    make clean >> $LOG_FILE 2>&1
    if [ $? -ne 0 ]; then
        echo "WML clean failed...Please see outfile for more details"
        exit -1
    else
        echo "WML clean successful"
    fi

    make >> $LOG_FILE 2>&1
	if [ $? -ne 0 ]; then
		echo "WML build failed...Please see outfile for more details"
		exit -1
	else
	        echo "WML build successful"
	fi
}

function main()
{
	echo "Building WML binaries... "
    buildwml
}

if [ $# -gt 1 ]
then
	echo "extra arguments"
	help_display
elif [ $# -eq 1 ] && [ $1 == "--help" ]
then
    help_display
elif [ $# -eq 1 ] && [ $1 == "--installpkg-only" ]
then
    install_pkg
elif [ $# -eq 0 ]
then
	echo "Building WML"
	main
else
    help_display
fi