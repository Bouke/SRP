test:
	swift test -c release -Xswiftc -enable-testing
test-with-python:
	PYTHON=`which python` swift test -c release -Xswiftc -enable-testing
