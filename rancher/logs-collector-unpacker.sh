#!/bin/bash
for file in $(ls | grep '.tar.gz'); do
  dirname=$(echo $file | cut -f1 -d. | perl -p -e 's/(.*)\-\d{4}\-\d{2}\-\d{2}_.*/$1/')
  mkdir $dirname;
  tar zxvf $file -C $dirname;
  mv $file $dirname/
done
