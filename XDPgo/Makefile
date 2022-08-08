CLANG ?= clang-14
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

format:
	find . -type f -name "*.c" | xargs clang-format -i

all: format $(addsuffix -el.elf,$(TARGETS)) $(addsuffix -eb.elf,$(TARGETS)) generate
	ln -srf testdata/loader-$(CLANG)-el.elf testdata/loader-el.elf
	ln -srf testdata/loader-$(CLANG)-eb.elf testdata/loader-eb.elf

# $BPF_CLANG is used in go:generate invocations.
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:

	go generate ./..

testdata/loader-%-el.elf: testdata/loader.c
	$* $(CFLAGS) -target bpfel -c $< -o $@

testdata/loader-%-eb.elf: testdata/loader.c
	$* $(CFLAGS) -target bpfeb -c $< -o $@

%-el.elf: %.c
	$(CLANG) $(CFLAGS) -target bpfel -c $< -o $@

%-eb.elf : %.c
	$(CLANG) $(CFLAGS) -target bpfeb -c $< -o $@

.PHONY: generate-btf
generate-btf: KERNEL_VERSION?=5.18
generate-btf:
	$(eval TMP := $(shell mktemp -d))
	curl -fL "$(CI_KERNEL_URL)/linux-$(KERNEL_VERSION).bz" -o "$(TMP)/bzImage"
	./testdata/extract-vmlinux "$(TMP)/bzImage" > "$(TMP)/vmlinux"
	$(OBJCOPY) --dump-section .BTF=/dev/stdout "$(TMP)/vmlinux" /dev/null | gzip > "btf/testdata/vmlinux.btf.gz"
	curl -fL "$(CI_KERNEL_URL)/linux-$(KERNEL_VERSION)-selftests-bpf.tgz" -o "$(TMP)/selftests.tgz"
	tar -xf "$(TMP)/selftests.tgz" --to-stdout tools/testing/selftests/bpf/bpf_testmod/bpf_testmod.ko | \
		$(OBJCOPY) --dump-section .BTF="btf/testdata/btf_testmod.btf" - /dev/null
	$(RM) -r "$(TMP)"
