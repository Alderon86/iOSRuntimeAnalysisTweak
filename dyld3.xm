// TRGoCPftF - dyld(3) Logger
// Use Fishhook to swap implementations to log dyld activity for
// jailed IPA.
// Don't do anything dumb with it

#import <mach-o/dyld.h>
#import <fishhook.h>
#import <dlfcn.h>

#pragma mark dyld Fishhook
// (1) _dyld_image_count
static uint32_t (*orig_dyld_image_count)(void);
// (2) _dyld_get_image_header
static const struct mach_header* (*orig_dyld_get_image_header)(uint32_t);
// (3) _dyld_get_image_vmaddr_slide
static intptr_t (*orig_dyld_get_image_vmaddr_slide)(uint32_t);
// (4) _dyld_get_image_name
static const char* (*orig_dyld_get_image_name)(uint32_t);
// (5) _dyld_register_func_for_add_image
static void (*orig_dyld_register_func_for_add_image)(void (*func)(const struct mach_header*,intptr_t));
// (6) _dyld_register_func_for_remove_image
static void (*orig_dyld_register_func_for_remove_image)(void (*func)(const struct mach_header*, intptr_t));
// (7) NSVersionOfRunTimeLibrary
static int32_t (*orig_NSVersionOfRunTimeLibrary)(const char*);
// (8) NSVersionOfLinkTimeLibrary
static int32_t (*orig_NSVersionOfLinkTimeLibrary)(const char*);
// (9) NSGetExecutablePath
static int (*orig_NSGetExecutablePath)(char *, uint32_t*);

// (1) Return count of all Images
uint32_t my_dyld_image_count(void) {
  uint32_t ret = orig_dyld_image_count();
  NSLog(@"[dyld(3)] - dyld get image count => %ul",ret);
  return ret;
}
// (2) Return Mach_Header from Image Index in Mach-O Binary
const struct mach_header* my_dyld_get_image_header(uint32_t image_index){
  const struct mach_header *head;
  head = orig_dyld_get_image_header(image_index);
  NSLog(@"[dyld(3)] - dyld get image header =>\n %@",head);
  return head;
}
// (3) Get Get The ASLR Slide address of Image at given Index
intptr_t my_dyld_get_image_vmaddr_slide(uint32_t image_index){
  intptr_t ret = orig_dyld_get_image_vmaddr_slide(image_index);
  NSLog(@"[dyld(3)] - dyld, Get Image ASLR Slide\n=>%lu",ret);
  return ret;
}
// (4) Return name of Image in Target Binary by Index in Image List
const char* my_dyld_get_image_name(uint32_t image_index){
  const char* name = orig_dyld_get_image_name(image_index);
  NSLog(@"[dyld(3)] - Get Image Name =>\n%s",name);
  return name;
}
// (5) Add Callback function to monitor for dyld image ~Addition~
//     Not a threadsafe function BTDubs
void my_dyld_register_func_for_add_image(void (*aFunc)(const struct mach_header* mh,intptr_t vmaddr_slide)){
  NSLog(@"[dyld(3)] - Register Func for add image Function() \n=> %p",aFunc);
  //NSLog(@"[dyld(3)] - Registered Functions passed Args\n=> %@\n=> %lu",mh,vmaddr_slide);
  NSLog(@"[dyld(3)] - Good Chance I fucked This Up Entirely");
}
// (6) Add Callback function to monitor for dyld image ~Removal~
void my_dyld_register_func_for_remove_image(void (*aFunc)(const struct mach_header* mh, intptr_t vmaddr_slide)){
  NSLog(@"[dyld(3)] - Register Func for remove image Function() \n=> %p",aFunc);
  //NSLog(@"[dyld(3)] - Registered Functions passed Args\n=> %@\n=> %lu",mh,vmaddr_slide);
  NSLog(@"[dyld(3)] - Good Chance I fucked This Up Entirely");
}
// (7) Fetch Version of RunTime Library by Library name
int32_t my_NSVersionOfRunTimeLibrary(const char* libName){
  int32_t ret = orig_NSVersionOfRunTimeLibrary(libName);
  NSLog(@"[dyld(3)] - Version of RunTimeLibrary for %s\nVersion: %X",libName,ret);
  return ret;
}
// (8) Feth Version of of LinkTime Library by Library Name
int32_t my_NSVersionOfLinkTimeLibrary(const char* libName){
  int32_t ret = orig_NSVersionOfLinkTimeLibrary(libName);
  NSLog(@"[dyld(3)] - Version of LinkTimeLibrary for %s\nVersion: %X",libName,ret);
  return ret;
}
// (9) Get Char* path buffer and Buffer Size for Target Executable
int my_NSGetExecutablePath(char * buffer, uint32_t *bufferSize) {
  int ret = orig_NSGetExecutablePath(buffer,bufferSize);
  NSLog(@"[dyld(3)] - NSGetExecutablePath buffer => %s",buffer);
  NSLog(@"[dyld(3)] - NSGetExecutablePath bufferSize => %p", bufferSize);
  NSLog(@"[dyld(3)] - NSGetExecutablePath Returned\n %d",ret);
  return ret;
}



#pragma mark constructure - Entry Point
%ctor {

  NSLog(@"[dyld(3)] - Init");

  rebind_symbols((struct rebinding[9]){
        {"_dyld_image_count", (void *)my_dyld_image_count, (void **)&orig_dyld_image_count},
        {"_dyld_get_image_header", (void *)my_dyld_get_image_header, (void **)&orig_dyld_get_image_header},
        {"_dyld_get_image_vmaddr_slide", (void *)my_dyld_get_image_vmaddr_slide,(void **)&orig_dyld_get_image_vmaddr_slide},
        {"_dyld_get_image_name", (void *)my_dyld_get_image_name, (void **)&orig_dyld_get_image_name},
        {"_dyld_register_func_for_add_image", (void *)my_dyld_register_func_for_add_image, (void **)&orig_dyld_register_func_for_add_image},
        {"_dyld_register_func_for_remove_image", (void *)my_dyld_register_func_for_remove_image, (void **)&orig_dyld_register_func_for_remove_image},
        {"NSVersionOfRunTimeLibrary", (void *)my_NSVersionOfRunTimeLibrary , (void **)&orig_NSVersionOfRunTimeLibrary},
        {"NSVersionOfLinkTimeLibrary", (void *)my_NSVersionOfLinkTimeLibrary, (void **)&orig_NSVersionOfLinkTimeLibrary},
        {"_NSGetExecutablePath", (void *)my_NSGetExecutablePath, (void **)&orig_NSGetExecutablePath}}, 9);

    NSLog(@"[dyld(3)] - Fishhook Symbol rebinding completed");

}
