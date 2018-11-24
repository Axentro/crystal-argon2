VERSION ?= 20171227
ARGON2 = phc-winner-argon2-$(VERSION)

all:
	curl -kL https://github.com/P-H-C/phc-winner-argon2/archive/$(VERSION).tar.gz | tar -xz
	cd $(ARGON2) && make

clean:
	rm -rf $(ARGON2)
