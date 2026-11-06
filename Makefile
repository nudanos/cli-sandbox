#!/usr/bin/make -f

SRCDIR		:= src/pam_sandbox
MY_CFLAGS	:= -fPIC
MY_CFLAGS	+= -Wall -Wextra -Werror
MY_CFLAGS	+= $(shell pkg-config --cflags libsystemd)

CFLAGS += $(MY_CFLAGS)

LDLIBS	+= $(shell pkg-config --libs libsystemd)
LDLIBS	+= -lpam
LDFLAGS	+= -shared
SRC	:= $(SRCDIR)/pam_sandbox.c
OBJ	:= $(SRC:.c=.o)

TARGET_LIB	:= $(SRCDIR)/pam_sandbox.so
PAM_MODULE_DIR ?= /usr/lib/security

all: $(TARGET_LIB)

$(TARGET_LIB): $(OBJ)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(OBJ) -o $(TARGET_LIB) $(LDFLAGS) $(LDLIBS)

%.o : %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

install: $(TARGET_LIB)
	install -D -m644 $(TARGET_LIB) $(DESTDIR)$(PAM_MODULE_DIR)/pam_sandbox.so
	mkdir -p $(DESTDIR)/opt/vyatta/share/pam-configs
	install -m644 $(SRCDIR)/pam-configs/sandbox \
		$(DESTDIR)/opt/vyatta//share/pam-configs/sandbox

clean:
	rm -f $(OBJ) $(TARGET_LIB)
