#define _GNU_SOURCE
#include "gotcha_dl.h"
#include "tool.h"
#include "libc_wrappers.h"
#include "elf_ops.h"
#include <dlfcn.h>

#if defined(__GLIBC__) && __GLIBC__ >= 2 && __GLIBC_MINOR__ < 34
void* _dl_sym(void* handle, const char* name, void* where);
#else
struct Addrs {
    ElfW(Addr) library_laddr;
    ElfW(Addr) lookup_addr;
};
int lib_header_callback(struct dl_phdr_info * info, size_t size, void * data) {
    struct Addrs* addrs = data;
    ElfW(Addr) end_addr = 0;
    for (int i=0;i<info->dlpi_phnum;++i) {
        ElfW(Addr) size = info->dlpi_phdr[i].p_vaddr + info->dlpi_phdr[i].p_memsz;
        if (end_addr < size) end_addr = size;
    }
    ElfW(Phdr) dlpi_phdr = info->dlpi_phdr[PT_PHDR];
    ElfW(Addr) base_addr = info->dlpi_addr;
    ElfW(Addr) end_phdr = base_addr + end_addr;
    if (base_addr <= addrs->lookup_addr && end_phdr >= addrs->lookup_addr)
        addrs->library_laddr = base_addr;
    return 0;
}
/**
 * This function looks for all symbols defined in rela or rel.
 *
 * @param name, symbol name
 * @param lmap, library where we search for symbol.
 * @return symbol pointer
 */
void *dl_lookup_symbol_x(const char *name, struct link_map *lmap) {
    INIT_DYNAMIC(lmap)
    ElfW(Addr) offset = lmap->l_addr;
    (void) offset;
    if (is_rela) {
        rela = (ElfW(Rela) *) jmprel;
        for (i = 0; i < rel_count; i++) {
          ElfW(Addr) offset = rela[i].r_offset;
          unsigned long symidx = R_SYM(rela[i].r_info);
          ElfW(Sym) *sym = symtab + symidx;
          char *symname = strtab + sym->st_name;
          if (strcmp(symname, name) == 0) {
            void **sym_ptr = (void **) (lmap->l_addr + offset);
            return *sym_ptr;
          }
       }
    } else {
        rel = (ElfW(Rel) *) jmprel;
        for (i = 0; i < rel_count; i++) {
            ElfW(Addr) offset = rel[i].r_offset;
            unsigned long symidx = R_SYM(rel[i].r_info);
            ElfW(Sym) *sym = symtab + symidx;
            char *symname = strtab + sym->st_name;
            if (strcmp(symname, name) == 0) {
                void **sym_ptr = (void **) (lmap->l_addr + offset);
                return *sym_ptr;
            }
        }
    }
    return NULL;
}

/**
 * Implement the logic of _dl_sym
 * 1. find the caller library using the program headers.
 * 2. find the first library which has the symbol for RTLD_DEFAULT
 * 3. find the second library which has the symbol for RTLD_NEXT
 * @param handle, handle for dl operation
 * @param name, name of the symbol
 * @param who, the virtual address of the caller
 * @return symbol pointer
 */

static void * _dl_sym(void *handle, const char *name, void *who) {
    ElfW(Addr) caller = (ElfW(Addr)) who;
    /* Iterative over the library headers and find the caller
     * the address of the caller is set in addrs->library_laddr
     **/
    struct Addrs addrs;
    addrs.lookup_addr = caller;
    dl_iterate_phdr(lib_header_callback, &addrs);

    struct link_map *lib_iter;
    int found_caller = 0;
    int found_sym = 0;
    for (lib_iter = _r_debug.r_map; lib_iter != 0; lib_iter = lib_iter->l_next) {
        /* find the library of the caller */
        if (lib_iter->l_addr == addrs.library_laddr)
            found_caller = 1;
        if (found_caller) {
            /* lookup symbol on the main caller or next lib which has symbol
             * This selection depends on RTLD_DEFAULT or RTLD_NEXT
             **/
            void* sym = dl_lookup_symbol_x(name, lib_iter);
            if (sym != NULL ) {
                if (handle == RTLD_DEFAULT) {
                    return sym;
                } else if (found_sym && handle == RTLD_NEXT){
                    return sym;
                }
                found_sym = 1;
            }
        }
    }
    return NULL;
}

#endif

gotcha_wrappee_handle_t orig_dlopen_handle;
gotcha_wrappee_handle_t orig_dlsym_handle;

static int per_binding(hash_key_t key, hash_data_t data, void *opaque KNOWN_UNUSED)
{
   int result;
   struct internal_binding_t *binding = (struct internal_binding_t *) data;

   debug_printf(3, "Trying to re-bind %s from tool %s after dlopen\n",
                binding->user_binding->name, binding->associated_binding_table->tool->tool_name);
   
   while (binding->next_binding) {
      binding = binding->next_binding;
      debug_printf(3, "Selecting new innermost version of binding %s from tool %s.\n",
                   binding->user_binding->name, binding->associated_binding_table->tool->tool_name);
   }
   
   result = prepare_symbol(binding);
   if (result == -1) {
      debug_printf(3, "Still could not prepare binding %s after dlopen\n", binding->user_binding->name);
      return 0;
   }

   removefrom_hashtable(&notfound_binding_table, key);
   return 0;
}

static void* dlopen_wrapper(const char* filename, int flags) {
   typeof(&dlopen_wrapper) orig_dlopen = gotcha_get_wrappee(orig_dlopen_handle);
   void *handle;
   debug_printf(1, "User called dlopen(%s, 0x%x)\n", filename, (unsigned int) flags);
   handle = orig_dlopen(filename,flags);

   debug_printf(2, "Searching new dlopened libraries for previously-not-found exports\n");
   foreach_hash_entry(&notfound_binding_table, NULL, per_binding);

   debug_printf(2, "Updating GOT entries for new dlopened libraries\n");
   update_all_library_gots(&function_hash_table);
  
   return handle;
}

static void* dlsym_wrapper(void* handle, const char* symbol_name){
  typeof(&dlsym_wrapper) orig_dlsym = gotcha_get_wrappee(orig_dlsym_handle);
  struct internal_binding_t *binding;
  int result;
  debug_printf(1, "User called dlsym(%p, %s)\n", handle, symbol_name);

  if(handle == RTLD_NEXT){
    return _dl_sym(RTLD_NEXT, symbol_name ,__builtin_return_address(0));
  }
  if(handle == RTLD_DEFAULT) {
    return _dl_sym(RTLD_DEFAULT, symbol_name,__builtin_return_address(0));
  }

  result = lookup_hashtable(&function_hash_table, (hash_key_t) symbol_name, (hash_data_t *) &binding);
  if (result == -1)
     return orig_dlsym(handle, symbol_name);
  else
     return binding->user_binding->wrapper_pointer;
}

struct gotcha_binding_t dl_binds[] = {
  {"dlopen", dlopen_wrapper, &orig_dlopen_handle},
  {"dlsym", dlsym_wrapper, &orig_dlsym_handle}
};     
void handle_libdl(){
  gotcha_wrap(dl_binds, 2, "gotcha");
}

