# Definitions
RM := `which rm`
CC := `which gcc`
APPNAME := scan_field_app
DISTDIR := ./application
SRCS = scan_field_app.c
OBJS = $(SRCS:.c=.o)

# All Target
all: $(APPNAME)

dist: all
	-rm -f -r $(DISTDIR)
	mkdir $(DISTDIR)
	cp $(APPNAME) $(DISTDIR)
	tar cvfz "$(DISTDIR).tar.gz" $(DISTDIR)
	rm -f -r $(DISTDIR)
	@echo 'Built distribution: \e[32m$(DISTDIR).tar.gz'

# Tool invocations
$(APPNAME): $(OBJS)
	rm -f $(APPNAME)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C Linker'
	#$(CC) -g3 -ldl $(SRCS) -o $(APPNAME)
	$(CC) -g3 $(SRCS) -o $(APPNAME) -ldl
	@echo 'Finished building target: $@'	
	@echo ' '

# Other Targets
clean:
	rm -f *.o $(APPNAME) "$(DISTDIR).tar.gz"
	-@echo ' '

test: all
	./$(APPNAME)
.PHONY: all clean dist
.SECONDARY:
