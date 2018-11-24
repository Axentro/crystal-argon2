VERSION ?= 20171227
ARGON2 = phc-winner-argon2-$(VERSION)

all:
	curl -kL https://github.com/P-H-C/phc-winner-argon2/archive/$(VERSION).tar.gz | tar -xz
	mv phc-winner-argon2-$(VERSION) argon2 && cd argon2 && make

clean:
	rm -rf argon2
