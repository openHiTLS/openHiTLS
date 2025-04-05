#!/bin/bash

CERT_FILE_DIR=$(cd $(dirname $0);pwd)
pem_files=$(find ${CERT_FILE_DIR} -name "*.pem")
for file in $pem_files
do
    echo $file
    sed -i '$d' $file
    sed -i '1d' $file
    newfile=$(echo $file | sed -e "s/.pem/.der/")
    base64 -d $file > $newfile
done

