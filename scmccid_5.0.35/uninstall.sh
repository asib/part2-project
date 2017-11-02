#!/bin/bash
# Uninstall script to remove scmccid driver bundle(s) in mac os.

echo "Uninstalling..."

ini_path=/usr/local/scm/ini
ini_path1=/usr/local/identiv/ini
bundle_path1=/usr/local/pcsc/drivers
bundle_path2=/usr/libexec/SmartCardServices/drivers
bundle_path3=/usr/local/lib/pcsc/drivers
bundle_path4=/usr/local/libexec/SmartCardServices/drivers

# Uninstallation of the ini directory
if [ -d $ini_path ]
then
	echo "Removing $ini_path"
	rm -rf $ini_path
fi

if [ -d $ini_path1 ]
then
	echo "Removing $ini_path1"
	rm -rf $ini_path1
fi

# Uninstallation of the driver bundles(s)
for bundle_path in \
	$bundle_path1 \
	$bundle_path2 \
	$bundle_path3 \
	$bundle_path4
	
do
	if [ -d $bundle_path ]
	then
		for bundle in `ls -d $bundle_path/scmccid*.bundle 2> /dev/null`
		do
			echo "Removing $bundle"
			rm -rf $bundle
		done
	fi
done

# Remove the receipt
rm -rf /Library/Receipts/scmccid*.pkg
rm -rf /private/var/db/receipts/com.scmmicro.drivers.scmccid*

echo "Uninstallation completed."

