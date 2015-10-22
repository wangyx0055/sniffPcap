CC			= gcc
CFLAGS		= -c -Wall #-D_GNU_SOURCE
LDFLAGS		= -lpcap
SOURCES		= mainSource.c
HEADERS		= sniffer.h
#SOURCES		=sniffEx.c
INCLUDES	= -I.
OBJECTS		= $(SOURCES:.c=.o)
TARGET		= sniffer

all: $(SOURCES) $(TARGET)

$(TARGET): $(OBJECTS) $(HEADERS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) $< -o $@

clean:
	rm -rf $(OBJECTS) $(TARGET)
