##
# BIOS advent of code
#
TASK ?= 1
# make file arguments: TASK
# 'make build' will create bios.bin for task1
# 'make TASK=2 build' will create bios.bin for task2
# make clean before making another task. PR welcom to make conditional make dependencies
# i use this 'make clean && make TASK=1 run'

#don't know why need the bash but aint working without
debug16: bios.bin
	bash -c "python run.py TASK=$(TASK) ATTACH"

debug: bios.bin
	bash -c "python run.py TASK=$(TASK) ATTACH_LONG"

run: bios.bin
	bash -c "python run.py TASK=$(TASK)"

bios.bin: main
	cat /dev/null | head -c 196608 > bios.bin && cat main >> bios.bin

main: bios.S
	nasm -D TASK_NR=$(TASK) bios.S -o $@

build: bios.bin

clean:
	rm main || true
	rm bios.bin || true

.PHONY: run debug clean build
.DEFAULT_GOAL := run

# end
