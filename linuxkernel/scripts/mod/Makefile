#hostprogs-y	:= modpost mk_podconfig mk_elfconfig
hostprogs-y	:= modpost mk_elfconfig
always		:= $(hostprogs-y) empty.o

modpost-objs	:= modpost.o file2alias.o sumversion.o

# dependencies on generated files need to be listed explicitly

$(obj)/modpost.o $(obj)/file2alias.o $(obj)/sumversion.o: $(obj)/elfconfig.h

#$(obj)/modpost.o $(obj)/file2alias.o $(obj)/sumversion.o: $(obj)/podconfig.h

quiet_cmd_elfconfig = MKELF   $@
      cmd_elfconfig = $(obj)/mk_elfconfig < $< > $@

#quiet_cmd_podconfig = MKPOD   $@
#      cmd_podconfig = $(obj)/mk_podconfig < $< > $@


$(obj)/elfconfig.h: $(obj)/empty.o $(obj)/mk_elfconfig FORCE
	$(call if_changed,elfconfig)

#$(obj)/podconfig.h: $(obj)/empty.o $(obj)/mk_podconfig FORCE
#	$(call if_changed,podconfig)

targets += elfconfig.h
#targets += podconfig.h
