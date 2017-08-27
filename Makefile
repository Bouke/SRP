test:
	PYTHON=`which python` swift test -c release -Xswiftc -enable-testing
debug-test:
	PYTHON=`which python` swift test -c release -Xswiftc -enable-testing -Xswiftc -D -Xswiftc DEBUG
