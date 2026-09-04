.PHONY: help install footage farm server c2 demo stop test clean logs

help:
	@echo "Prahari — SIH26187"
	@echo ""
	@echo "  make install   install python dependencies"
	@echo "  make footage   render the synthetic border footage (once, ~60s)"
	@echo "  make demo      start everything: DVR farm + mock C2 + server"
	@echo "  make stop      stop everything"
	@echo "  make test      run the end-to-end verification"
	@echo "  make logs      tail all three logs"
	@echo ""
	@echo "  dashboard      http://127.0.0.1:8000"

install:
	pip install --break-system-packages -r requirements.txt

footage:
	python3 -m prahari.sim.footage

farm:
	scripts/farm.sh start

server:
	scripts/server.sh start

c2:
	scripts/c2.sh start

demo: footage
	scripts/farm.sh start 5
	scripts/c2.sh start
	scripts/server.sh start 8
	@python3 -m prahari.tools.register_c2 || true
	@echo ""
	@echo "  Prahari is up.  Dashboard: http://127.0.0.1:8000"
	@echo "  Mock C2 output:  tail -f /tmp/prahari-c2.log"
	@echo ""

stop:
	-scripts/server.sh stop
	-scripts/c2.sh stop
	-scripts/farm.sh stop

test:
	python3 -m tests.test_alerts
	python3 -m tests.test_e2e

logs:
	tail -n 30 /tmp/prahari-farm.log /tmp/prahari-server.log /tmp/prahari-c2.log

clean:
	rm -f prahari.db prahari.db-wal prahari.db-shm .*.pid
	rm -rf evidence __pycache__ */__pycache__ */*/__pycache__
