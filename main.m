#import "main.h"
//#import "getBootManifest.c"
#import "pathfinder64.c"

extern int get_boot_manifest_hash(char hash[97]);
extern int print_boot_manifest_hash_main(int argc, char* argv[]);

@interface MyUtilityClass : NSObject
+ (NSArray *)runWithCommand:(const char *)cmd arguments:(char * const *)args;
@end

@implementation MyUtilityClass
+ (NSArray *)runWithCommand:(const char *)cmd arguments:(char * const *)args {
    int pid = 0;
    int retval = 0;

    // Set up environment with additional directories in PATH
    const char *env[] = {
        "PATH=/usr/local/sbin:/var/jb/usr/local/sbin:"
        "/usr/local/bin:/var/jb/usr/local/bin:"
        "/usr/sbin:/var/jb/usr/sbin:"
        "/usr/bin:/var/jb/usr/bin:"
        "/sbin:/var/jb/sbin:"
        "/bin:/var/jb/bin:"
        "/usr/bin/X11:/var/jb/usr/bin/X11:"
        "/usr/games:/var/jb/usr/games",
        "NO_PASSWORD_PROMPT=1",
        NULL
    };
    
    // Create a pipe to capture the output
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        perror("pipe");
        return @[@(errno), @""];
    }

    // Set up redirection of standard output to the write end of the pipe
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addclose(&actions, pipefd[0]);
    posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&actions, pipefd[1]);

    // Set up environment
    char *const *envp = (char *const *)env;

    retval = posix_spawn(&pid, cmd, &actions, NULL, args, envp);
    posix_spawn_file_actions_destroy(&actions);
    
    if (retval != 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return @[@(retval), @""];
    }

    // Close the write end of the pipe as we only need to read
    close(pipefd[1]);

    // Read from the read end of the pipe in chunks
    NSMutableData *outputData = [NSMutableData data];
    char buffer[1024];
    ssize_t bytesRead;
    while ((bytesRead = read(pipefd[0], buffer, sizeof(buffer))) > 0) {
        [outputData appendBytes:buffer length:bytesRead];
    }
    close(pipefd[0]); // Close the read end of the pipe

    if (bytesRead < 0) {
        return @[@(errno), @""];
    }

    // Wait for the child process to terminate
    int status;
    waitpid(pid, &status, 0);

    NSString *outputString = [[NSString alloc] initWithData:outputData encoding:NSUTF8StringEncoding];
    
    return @[@(status), outputString ?: @""];
}

@end

int pathKernelINST(uint32_t offset, uint32_t instPath, uint32_t instOriginal) {
    uint64_t addr;
    kbase(&addr);

    if (addr == 0) {
        NSLog(@"We couldn't get the base addr\n");
        return -1;
    }

    uint32_t value;
    int result = kread(addr + offset, &value, sizeof(value));  // Read exactly 4 bytes (sizeof(uint32_t))
    if (result != 0) {  // Assuming 0 is success
        NSLog(@"Failed to read kernel memory\n");
        return -1;
    }

    NSLog(@"kread returned: 0x%X in addr: 0x%llx\n", value, addr + offset);

    if (value != instPath) {
		if (value == instOriginal || instOriginal == 0) {
			int retv = kwrite(&instPath, (uint64_t)(addr + offset), sizeof(instPath));
			if (retv == 0) {
    			uint32_t newValue;
				kread(addr + offset, &newValue, sizeof(newValue));  // Read exactly 4 bytes (sizeof(uint32_t))
                
                NSLog(@"Successfully patched inst, kread executed again, it returned: 0x%X in addr: 0x%llx\n", newValue, addr + offset);
            } else {
                NSLog(@"Failed to write kernel memory\n");
                return -1;
            }
        } else {
            NSLog(@"Incorrect instruction, it appears we're not at the correct location");
			return -1;
        }
    } else {
        NSLog(@"Instruction is already patched");
    }

    return 0;
}

int pathAslr(void* kernel_buf, size_t kernel_len, int disable) {
    
    NSLog(@"%s: Entering ...\n",__FUNCTION__);

    char img4_sig_check_string[7] = "__XHDR";
    void* ent_loc = memmem(kernel_buf,kernel_len,img4_sig_check_string, 7);
    if(!ent_loc) {
        NSLog(@"%s: Could not find \"__XHDR, OMITING PATCHING...\" string\n",__FUNCTION__);
        return -1;
    }

    addr_t ent_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!ent_ref) {
        NSLog(@"%s: Could not find \"__XHDR\" xref\n",__FUNCTION__);
        return -1;
    }
    
    addr_t start_func = bof64(kernel_buf,0, ent_ref);
    if(!start_func) {
        NSLog(@"%s: Could not find load load_code_signature start\n",__FUNCTION__);
        return -1;
    }

    // check for ios 15
    uint32_t tbnz1_ref = step64_back(kernel_buf, (start_func + 0x374), 150 * 4, 0x36000000, 0x7E000000);
    uint32_t instMemValToCheck = *((uint32_t *)(kernel_buf + (tbnz1_ref - 0x4))); // on ios 15 before the tbnz function it has the ldrb function that we need to path

    if (instMemValToCheck == 0x394122C8)
    {
        NSLog(@"ios 15 Detected!\n");
        uint32_t originalOpcode = *((uint32_t *)(kernel_buf + (tbnz1_ref - 0x4)));
		pathKernelINST((uint32_t)(tbnz1_ref - 0x4), disable ? originalOpcode : 0xd2800408, disable ? 0 : originalOpcode);
        return 0;
    }
    
    ent_ref = xref64code(kernel_buf,0,(addr_t)GET_OFFSET(kernel_len, start_func), start_func);
    if(!ent_ref) {
        NSLog(@"%s: Could not find load_code_signature xref to load_machfile\n",__FUNCTION__);
        return -1;
    }

    addr_t tbnz_ref = step64_back(kernel_buf, ent_ref, 150 * 4, 0x36000000, 0x7E000000);
    if(!tbnz_ref) {
        printf("%s: Could not find tbnz\n",__FUNCTION__);
        return -1;
    }

    uint32_t memValToCheck = *((uint32_t *)(kernel_buf + (tbnz_ref - 0x8))); // ios 14 is 8 bytes before
    uint32_t memValToCheck4 = *((uint32_t *)(kernel_buf + (tbnz_ref - 0x4))); // ios 13 is 4 bytes before
    
    if (memValToCheck == 0x394122c8) {
	    uint32_t originalOpcode = *((uint32_t *)(kernel_buf + (tbnz_ref - 0x8)));
    	pathKernelINST((uint32_t)(tbnz_ref - 0x8), disable ? originalOpcode : 0xd2800408, disable ? 0 : originalOpcode);

    } else if (memValToCheck4 == 0x394122c8) {
	    uint32_t originalOpcode = *((uint32_t *)(kernel_buf + (tbnz_ref - 0x4)));
		pathKernelINST((uint32_t)(tbnz_ref - 0x4), disable ? originalOpcode : 0xd2800408, disable ? 0 : originalOpcode);
    
	} else {
        NSLog(@"we couldn't find the instruction to path");
        return -1;
    }

    return 0;
}

int pathKernel(int disable) {
	void* kernel_buf;
    size_t kernel_len;
    
	FILE* fp = NULL;
    fp = fopen("/var/tmp/kcache.raw", "rb");
    if(!fp) {
        NSLog(@"Error opening /var/tmp/kcache.raw !\n");
        return -1;
    }
    
    fseek(fp, 0, SEEK_END);
    kernel_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    kernel_buf = (void*)malloc(kernel_len);

    if(!kernel_buf) {
        NSLog(@"%s: Out of memory!\n", __FUNCTION__);
        fclose(fp);
        return -1;
    }
    
    fread(kernel_buf, 1, kernel_len, fp);
    fclose(fp);
    
    if(memmem(kernel_buf,kernel_len,"KernelCacheBuilder",18)) {
        NSLog(@"%s: Detected IMG4/IM4P, you have to unpack and decompress it!\n",__FUNCTION__);
        return -1;
    }
    
    if (*(uint32_t*)kernel_buf == 0xbebafeca) {
        NSLog(@"%s: Detected fat macho kernel\n",__FUNCTION__);
        memmove(kernel_buf,kernel_buf+28,kernel_len);
	}

	pathAslr(kernel_buf, kernel_len, disable);

	free(kernel_buf);
	return 0;
}

int main(int argc, char *argv[], char *envp[]) {
    @autoreleasepool {
		bool isRootless = true;
    	if (access("/private/var/jb/", F_OK) != 0) {
    	    isRootless = false;
    	} else isRootless = true;

		char hash[97];
		int retmnf = get_boot_manifest_hash(hash);
		if (retmnf != 0) {
    		fprintf(stderr, "could not get boot manifest hash\n");
    		return retmnf;
		}
		
		NSString *hashNS = @(hash);
		NSString *pathSTR = [NSString stringWithFormat:@"/private/preboot/%@/System/Library/Caches/com.apple.kernelcaches/kernelcache", hashNS];
		const char *path = [pathSTR UTF8String];

		int doesKernelExist = access(path, F_OK);  
		if (doesKernelExist != 0) {
			NSLog(@"Kernel file does not exist on: %s", path);
            return -1;
		}

    	const char *img4BinPath = isRootless ? "/var/jb/usr/bin/img4" : "/usr/bin/img4";
    	const char *args_img4[] = {
    	    img4BinPath,
			"-i",
			path,
			"-o",
			"/var/tmp/kcache.raw",
    	    NULL
    	};
    	char* const *args_img4Ptr = (char * const *)args_img4;

		NSArray *img4Return = [MyUtilityClass runWithCommand:args_img4[0] arguments:args_img4Ptr];

		if (access("/var/tmp/kcache.raw", F_OK) != 0) {
			NSLog(@"img4 failed to create /var/tmp/kcache.raw, output of the img4 cmd was: %@", img4Return[1]);
			if (img4Return[1] == nil || [img4Return[1] isEqualToString:@""]) {
				NSLog(@"Please ensure img4 is installed, use apt install img4lib to install it");
			}
			
            return -1;
		}

        // Check command-line arguments
        int disable = 0;
        if (argc > 1 && strcmp(argv[1], "--disable-path") == 0) {
            NSLog(@"Disabling the aslr path patch...");
            disable = 1;
        } else {
            NSLog(@"Applying the aslr path patch...");
        }

		pathKernel(disable);
	}
}
