#!/bin/bash
#
# This will automatically set up a screenshot region, then
# copy it to the clipboard and save to a file in the prescribed
# format. Update to your prefered location.
#
# Add to Kali bar using:
#	- Right Click > Panel > Add New Items
#	- Add "Launcher"
#	- Right click Launcer and move to prefered location
#	- Right click Launcher > Properties
#		- Add new empty item to launcher
#		- Name: Screenshot
#		- Cmd: Whereever this script is
#		- Icon: Select an icon
#
# If wish to auto-cfg:
# - need to update with plugin id position and property data:
# 	~/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-panel.xml
# - add launcher in right location. e.g. if id 21:
# 	~/.config/xfce4/panel/launcher-21/16655615531.desktop
#

saveLocation="/hgfs/vmshare/screenshots"

if [ ! -d "$saveLocation" ]; then
	/usr/bin/zenity --warning --text="$saveLocation does not exist"
	exit -1
fi

# Generate date-time format:
# Screenshot_2022-10-12_08-10-06_735344872.jpg
saveFile=`/usr/bin/date +'Screenshot_%Y-%m-%d_%H-%m-%S_%N.jpg'`
saveFullPath="${saveLocation}/${saveFile}"

/usr/bin/xfce4-screenshooter -c -r -s "$saveFullPath"
