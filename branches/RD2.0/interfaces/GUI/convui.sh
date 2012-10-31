#!/bin/bash

mv GUI/uifiles/__init__.py GUI/uifiles/blah
rm GUI/uifiles/*.py
rm GUI/uifiles/*.pyc
mv GUI/uifiles/blah GUI/uifiles/__init__.py

FILES=GUI/uifiles/*.ui
ext=".py"

for UI in $FILES
do
	pyname=$(echo $UI | sed -e 's/\./_/')
	pyname=$pyname$ext

	pyuic4 $UI -o $pyname
	
done

