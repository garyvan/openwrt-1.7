#
# Building a vDSO image for AArch64.
#
# Author: Will Deacon <will.deacon@arm.com>
# Heavily based on the vDSO Makefiles for other archs.
#

obj-vdso_ilp32 := gettimeofday_ilp32.o note_ilp32.o sigreturn_ilp32.o

# Build rules
targets := $(obj-vdso_ilp32) vdso_ilp32.so vdso_ilp32.so.dbg
obj-vdso_ilp32 := $(addprefix $(obj)/, $(obj-vdso_ilp32))

ccflags-y := -shared -fno-common -fno-builtin
ccflags-y += -nostdlib -Wl,-soname=linux-vdso.so.1 \
		$(call cc-ldoption, -Wl$(comma)--hash-style=sysv)

obj-y += vdsoilp32.o
extra-y += vdso_ilp32.lds vdso-ilp32-offsets.h
CPPFLAGS_vdso_ilp32.lds += -P -C -U$(ARCH) -mabi=ilp32
CPPFLAGS_vdso.lds += -P -C -U$(ARCH)


# Force dependency (incbin is bad)
$(obj)/vdsoilp32.o : $(obj)/vdso_ilp32.so

# Link rule for the .so file, .lds has to be first
$(obj)/vdso_ilp32.so.dbg: $(src)/vdso_ilp32.lds $(obj-vdso_ilp32)
	$(call if_changed,vdsoilp32ld)

# Strip rule for the .so file
$(obj)/%.so: OBJCOPYFLAGS := -S
$(obj)/%.so: $(obj)/%.so.dbg FORCE
	$(call if_changed,objcopy)

# Generate VDSO offsets using helper script
gen-vdsosym := $(srctree)/$(src)/../vdso/gen_vdso_offsets.sh
quiet_cmd_vdsosym = VDSOSYM $@
define cmd_vdsosym
	$(NM) $< | $(gen-vdsosym) | LC_ALL=C sort > $@ && \
	cp $@ include/generated/
endef

$(obj)/vdso-ilp32-offsets.h: $(obj)/vdso_ilp32.so.dbg FORCE
	$(call if_changed,vdsosym)

# Assembly rules for the .S files
$(obj)/gettimeofday_ilp32.o: $(src)/../vdso/gettimeofday.S
	$(call if_changed_dep,vdsoilp32as)

$(obj)/note_ilp32.o: $(src)/../vdso/note.S
	$(call if_changed_dep,vdsoilp32as)

$(obj)/sigreturn_ilp32.o: $(src)/../vdso/sigreturn.S
	$(call if_changed_dep,vdsoilp32as)

# Actual build commands
quiet_cmd_vdsoilp32ld = VDSOILP32L $@
      cmd_vdsoilp32ld = $(CC) $(c_flags) -mabi=ilp32 -Wl,-T $^ -o $@
quiet_cmd_vdsoilp32as = VDSOILP32A $@
      cmd_vdsoilp32as = $(CC) $(a_flags) -mabi=ilp32 -c -o $@ $<


# Install commands for the unstripped file
quiet_cmd_vdso_install = INSTALL $@
      cmd_vdso_install = cp $(obj)/$@.dbg $(MODLIB)/vdso/$@

vdso_ilp32.so: $(obj)/vdso_ilp32.so.dbg
	@mkdir -p $(MODLIB)/vdso
	$(call cmd,vdso_install)

vdso_install: vdso_ilp32.so
