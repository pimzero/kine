#/bin/sh

VERBOSE=1

BIN=$1
ROM=$2

check() {
	local RET=KO
	local OUTPUT=$(mktemp)
	timeout 1 $@ >"$OUTPUT" 2>&1

	if [ "$?" -eq 124 ]; then
		RET=OK
	fi
	echo "[$RET] $@"

	if [ "$RET" = "KO" -a "$VERBOSE" -ge 1 ]; then
		while read LINE ; do
			echo "  > $LINE" ;
		done <"$OUTPUT"
	fi

	rm "$OUTPUT"
}

check "$BIN" "$ROM"

check "$BIN" "$ROM" -r noop
check "$BIN" "$ROM" -r sdl2
check "$BIN" "$ROM" -r sdl3

check "$BIN" "$ROM" -M auto

check "$BIN" "$ROM" -M ptrace
check "$BIN" "$ROM" -M syscall_user_dispatch

check "$BIN" "$ROM" -T -Mptrace
check "$BIN" "$ROM" -T -Msyscall_user_dispatch

check "$BIN" "$ROM" -s -Mptrace
check "$BIN" "$ROM" -s -Msyscall_user_dispatch

check "$BIN" "$ROM" -s -T -Mptrace
check "$BIN" "$ROM" -s -T -Msyscall_user_dispatch

check "$BIN" "$ROM" -C -T -Mptrace
check "$BIN" "$ROM" -C -T -Msyscall_user_dispatch
