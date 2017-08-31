MODULE=pam_honeyword

CC=/usr/bin/gcc
LD=/usr/bin/ld


CC_FLAGS=-lpam -fPIC -O2
LD_FLAGS=-x --shared

all: $(MODULE).c
	$(CC) $(CC_FLAGS) -o $(MODULE).o -c $(MODULE).c
	$(LD) $(LD_FLAGS) -o $(MODULE).so $(MODULE).o

clean:
	rm -f $(MODULE).so $(MODULE).o

