VERSION			= 0.0.1
CC				= gcc
WFLAGS			= -Wall -Wextra -Wfloat-equal -Wundef -Wshadow -Wpointer-arith \
				  -Wstrict-prototypes -Wstrict-overflow=5 -Wwrite-strings \
				  -Waggregate-return -Wcast-qual -Wswitch-default -Wswitch-enum \
				  -Wunreachable-code
OPTIMIZE		= -Ofast
CFLAGS			= $(WFLAGS) $(OPTIMIZE) -static
LIBS			= -lssl -lcrypto -lpthread
OBJS			= hbad.o
NAME			= hbad
BINDIR			= bin

program			: $(OBJS)
		$(CC) -o $(NAME) $(OBJS) $(LIBS)

%.o				: %.h
%.o 			: %.c
		$(CC) -c $(CFLAGS) $<

install			:
		install --mode 755 $(NAME) $(BINDIR)/

uninstall		:
		rm $(BINDIR)/$(NAME)

clean			:
		rm *.o $(NAME)
