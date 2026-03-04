#!/bin/bash

set -e

session="nmrpfuzz-$1"
fuzz_in=$(dirname "$0")/fuzzin
fuzz_out=$(dirname "$0")/fuzzout/sync

get_fuzz_cmd()
{
	[[ $# -eq 2 ]] || exit 1

	if [[ $1 == "tftp" ]]; then
		prog_args="$fuzz_in/tftp.bin"
	fi

	if [[ $2 -eq 0 ]]; then
		par_flag="-M"
	else
		par_flag="-S"
	fi

	echo "afl-fuzz -t 1000 -i $fuzz_in/$1 -o $fuzz_out/$1 $par_flag $session$2 -- ./fuzz $1 $prog_args"
}

if [[ $1 != "tftp" && $1 != "nmrp" ]]; then
	echo >&2 "usage: $0 [tftp|nmrp]"
	exit 1
fi

make fuzz
! tmux kill-session -t "$session:"

! rm -rf $fuzz_out
mkdir -p $fuzz_out

echo "Will prompt to change core dump notification settings and cpu scaling"
echo core | sudo tee /proc/sys/kernel/core_pattern
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

if [[ $2 == "single" ]]; then
	exec $(get_fuzz_cmd "$1" 0)
fi

tmux new-session -d -s "$session" "$(get_fuzz_cmd "$1" 0)"
n=$(getconf _NPROCESSORS_ONLN)

if [[ $n -ge 4 ]]; then
	let n=$n-3
else
	n=1
fi

i=1

while [[ $i -lt $n ]]; do
	tmux new-window -t "$session:" "$(get_fuzz_cmd "$1" $i)"
	let i=$i+1
done

tmux attach