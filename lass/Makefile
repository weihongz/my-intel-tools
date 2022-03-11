BIN = ax cpuid cpu_feature hello_ins hello_sys \
        uname uname_sys t he cpu_num cmd he Hello_World t_32 hh tc_32 tc \
        Hello sleep

all: $(BIN)

$(all):
	$(CC) -o $@ $<

hello_ins:
	as -o hello_ins.o hello_ins.S
	ld -o hello_ins hello_ins.o

he:
	as --32 -o he.o hello_ins.S
	ld -melf_i386 -o he he.o

Hello_World:
	as --32 -o hello.o hello.s
	ld -melf_i386 -o Hello_World hello.o --oformat=binary

t:
	as -o t.o t.S
	ld -o t t.o

t_32:
	as --32 -o t_32.o t_32.S
	ld -melf_i386 -o t_32 t_32.o

tc_32:
	as --32 -o tc_32.o tc_32.S
	ld -melf_i386 -o tc_32 tc_32.o

tc:
	as -o tc.o tc.S
	ld -o tc tc.o

hh:
	as --32 -o hh.o hh.s
	ld -melf_i386 -o hh hh.o

cpuid:

clean:
	rm -f $(BIN) *.o *.out
