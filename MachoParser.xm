// TRGoCPftF - Simple Mach-O executable analysis tools
// Injectable Tweak for reading header and dynamic linker calls
// Created 09/11/19

// May be useful for some runtime check bypasses :eyes:

#import <stdlib.h>
#import <stdio.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <uuid/uuid.h>

// Check Header architecture (32 vs 64 bit) at a given image index
bool arch_is_64(uint32_t image_index)
{
  const struct mach_header* header = (struct mach_header *)_dyld_get_image_header(image_index);
  if(header->magic == MH_MAGIC_64 || header->magic == MH_CIGAM_64)
  {return true;}
  else
  {return false;}
}

// Get image index for target image based on partial name comparison
// Ex) const char* target = "myapp.app/myapp";
uint32_t get_image_index(const char* comp_name)
{
  uint32_t image_index;
  uint32_t total_images = _dyld_image_count();

  for(int i = 0; i < total_images; i++)
  {
    const char* full_image_name = _dyld_get_image_name(i);

    if(strstr(full_image_name, comp_name)){
      image_index = (uint32_t)i;
      NSLog(@"[MachO]: \nFound image match:\n%s",full_image_name);
      return image_index;
    }
  }
  NSLog(@"[MachO]: \nFailed to find image matching %s", comp_name);
  // Add Proper Error Handling when Image can't be identified //
  return 9999999;
}

void parseHeader(const struct mach_header_64* header){

  uint8_t *cmdPtr = (uint8_t *)header;
  cmdPtr += sizeof(struct mach_header_64);
  // Grab 1st load command after header, by shifting cmd pointer forward the size of header struct

  for(int i = 0; i < header->ncmds > 0; i++)
  {
    struct load_command *loadCMD = (load_command *)cmdPtr;
    NSLog(@"[MachO]: \nLoad Cmd Type: 0x%x\nLoad Cmd Size: 0x%x",loadCMD->cmd,loadCMD->cmdsize);

    if(loadCMD->cmd == LC_CODE_SIGNATURE) {

      struct linkedit_data_command *CSCMD = (struct linkedit_data_command *)loadCMD;
      NSLog(@"[MachO]: \nLC_CODE_SIGNATURE \ncmd-> 0x%x\ncmdsize-> 0x%x\ndataoff-> 0x%x\ndatasize-> 0x%x",CSCMD->cmd,CSCMD->cmdsize,CSCMD->dataoff,CSCMD->datasize);

    } else if(loadCMD->cmd == LC_ENCRYPTION_INFO_64) {

      struct encryption_info_command_64 *cryptCMD = (struct encryption_info_command_64 *)loadCMD;
      NSLog(@"[MachO]: \nLC_ENCRYPTION_INFO\ncmd-> 0x%x\n cmdsize-> 0x%x\ncryptoff-> 0x%x\ncryptsize-> 0x%x\ncryptid-> 0x%x\npad-> 0x%x", cryptCMD->cmd,cryptCMD->cmdsize,cryptCMD->cryptoff,cryptCMD->cryptsize,cryptCMD->cryptid,cryptCMD->pad);
      //cryptCMD->cryptid = 1;
      //NSLog(@"[MachO]: \nLC_ENCRYPTION_INFO\ncmd-> 0x%x\n cmdsize-> 0x%x\ncryptoff-> 0x%x\ncryptsize-> 0x%x\ncryptid-> 0x%x\npad-> 0x%x", cryptCMD->cmd,cryptCMD->cmdsize,cryptCMD->cryptoff,cryptCMD->cryptsize,cryptCMD->cryptid,cryptCMD->pad);
      NSLog(@"[MachO]: \ncryptoff addr: %p",&cryptCMD->cryptid);
    } else if(loadCMD->cmd == LC_SEGMENT_64) {

      struct segment_command_64 *segCMD = (struct segment_command_64 *)loadCMD;
      NSLog(@"[MachO]: \nSegment Name: %s\n size: 0x%x\nnsects: 0x%x",segCMD->segname,segCMD->cmdsize,segCMD->nsects);
      uint8_t *sectPtr = (uint8_t *)(segCMD+1);

      for(uint32_t i = 0; i < segCMD->nsects; ++i)
      {
        struct section_64 *sect = (struct section_64 *)sectPtr;
        NSLog(@"[MachO]: \n  (segment,section): (%s,%s)\naddr: %llx\nsize: 0x%llx\noffset: 0x%x\nalign: 0x%x\nreloff: 0x%x\nnreloc: 0x%x\nflags: 0x%x",sect->segname,sect->sectname,sect->addr,sect->size,sect->offset,sect->align,sect->reloff,sect->nreloc,sect->flags);
        sectPtr += sizeof(struct section_64);
      }

    } else if(loadCMD->cmd == LC_MAIN) {

      const struct entry_point_command *epCMD = (struct entry_point_command *)loadCMD;
      uint64_t entryoff = epCMD->entryoff;
      NSLog(@"[MachO]: \nLoaded LC_Main\nEntry Point Offset 0x%llx",entryoff);

    } else if(loadCMD->cmd == LC_LOAD_DYLIB){

      const struct dylib_command *dylibCMD = (struct dylib_command *)loadCMD;
      const struct dylib aDylib = (struct dylib)dylibCMD->dylib;
      uint8_t *namePtr = (uint8_t *)loadCMD;
      char *name = (char *)(namePtr + aDylib.name.offset);

      NSLog(@"[MachO]: \nLC_LOAD_DYLIB:\ncmd-> 0x%x\ncmdsize-> 0x%x \nDylib:\nName: %s\ntimestamp-> 0x%x\ncurrent_version-> 0x%x\ncompatiability_version-> 0x%x",dylibCMD->cmd,dylibCMD->cmdsize,name,aDylib.timestamp,aDylib.current_version,aDylib.compatibility_version);
      //NSLog(@"[MachO]: \nDylib:\nName: %s\ntimestamp-> 0x%x\ncurrent_version-> 0x%x\ncompatiability_version-> 0x%x",name,aDylib.timestamp,aDylib.current_version,aDylib.compatibility_version);
    } else if(loadCMD->cmd == LC_SYMTAB) {

      const struct symtab_command *symtabCMD = (struct symtab_command *)loadCMD;
      NSLog(@"[MachO]: \nLC_SYMTAB \ncmd-> 0x%x\ncmdsize-> 0x%x\nsymoff-> 0x%x\nnsyms-> 0x%x\nstroff-> 0x%x\nstrsize-> 0x%x",symtabCMD->cmd,symtabCMD->cmdsize,symtabCMD->symoff,symtabCMD->nsyms,symtabCMD->stroff,symtabCMD->strsize);

    } else if(loadCMD->cmd == LC_DYSYMTAB) {

      const struct dysymtab_command *dysymCMD = (struct dysymtab_command *)loadCMD;
      NSLog(@"[MachO]: \nLC_DYSYMTAB\ncmd-> 0x%x\ncmdsize-> 0x%x",dysymCMD->cmd,dysymCMD->cmdsize);

    } else if(loadCMD->cmd == LC_LOAD_DYLINKER) {

      const struct dylinker_command *dylinkerCMD = (struct dylinker_command *)loadCMD;
      uint8_t *namePtr = (uint8_t *)loadCMD;
      char *name = (char *)(namePtr + dylinkerCMD->name.offset);
      NSLog(@"[MachO]: \nLC_LOAD_DYLINKER\nname-> %s\ncmd-> 0x%x\ncmdsize-> 0x%x",name,dylinkerCMD->cmd,dylinkerCMD->cmdsize);

    } else if(loadCMD->cmd == LC_UUID) {

      const struct uuid_command *uuidCMD = (struct uuid_command *)loadCMD;
      NSLog(@"[MachO]: \nUUID_COMMAND\ncmd-> 0x%x\ncmdsize-> 0x%x\nuuid-> %s",uuidCMD->cmd,uuidCMD->cmdsize,uuidCMD->uuid);

    } else if(loadCMD->cmd == LC_VERSION_MIN_IPHONEOS) {

      const struct version_min_command *minCMD = (struct version_min_command *)loadCMD;
      NSLog(@"[MachO]: \nVERSION_MIN_COMMAND\ncmd-> 0x%x\ncmdsize-> 0x%x\nversion-> 0x%x\nsdk-> 0x%x",minCMD->cmd,minCMD->cmdsize,minCMD->version,minCMD->sdk);

    } else if(loadCMD->cmd == LC_SOURCE_VERSION) {

      const struct source_version_command *versCMD = (struct source_version_command *)loadCMD;
      NSLog(@"[MachO]: \nSOURCE_VERSION_COMMAND\ncmd-> 0x%x\ncmdsize-> 0x%x\version-> %llu",versCMD->cmd,versCMD->cmdsize,versCMD->version);

    }

    cmdPtr += loadCMD->cmdsize;
  }
}



//Lets do some shit
%ctor{
  NSLog(@"[MachO]: \nexec(./FuckBitches) && exec(./GetMoney)");


  const char* target = "****************";
  uint32_t target_index = get_image_index(target);
  bool target_arch = arch_is_64(target_index);
  NSLog(@"[MachO]: \ntarget: %s\ntarget_index: %u\nis_64: %d",target,target_index,target_arch);

  if(target_arch) {
    // load up header for 64 bit Arch
    const struct mach_header_64* header = (struct mach_header_64 *)_dyld_get_image_header(target_index);
    NSLog(@"[MachO]: Header Info \nFiletype: 0x%x\nNumber of Load Commands: %u\nSize Of All Load Commands: 0x%x\nFlags: 0x%x",header->filetype,header->ncmds,header->sizeofcmds,header->flags);
    // Lets actually start looking at stuff
    parseHeader(header);

  } else {
    // 32 bit Arch
    const struct mach_header* header = (struct mach_header *)_dyld_get_image_name(target_index);
    NSLog(@"[MachO]: \nload 32 bit header, Magic => %u",header->magic);
    // I'll get to it, who the fuck still uses 32 bit iOS products anyway?
  }

}
