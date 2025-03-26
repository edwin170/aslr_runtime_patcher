# aslr_runtime_patcher

**aslr_runtime_patcher** is a tool that disables ASLR (Address Space Layout Randomization) for the next binaries that will be executed. This patch is particularly useful for reverse engineering and testing.

> **Warning:** If left active, this patch may cause random reboots after several minutes. so the recommended workflow is to patch the kernel, launch your target app, and then disable the patch (this will avoid reboot problem). the patch works best when applied to the kernel before booting (using tools like [kernel64patcher](https://github.com/edwin170/Kernel64Patcher). or pongoOS module [disable_aslr](https://github.com/edwin170/disable_aslr)).

---

## Requirements

- **libkrw**
- **img4lib**

Ensure that both libraries are installed and properly configured on your device.

---

## Usage

- **Apply the Patch:**  
  Simply run the tool without any arguments to disable ASLR for subsequent binaries:
  ```sh
  ./aslrruntimepatcher

- **Disable the Patch:**
    To restore the original ASLR behavior and prevent system instability, run:
    ```sh
    ./aslrruntimepatcher --disable-path

## credits
* xerub for patchfinder64
* iH8sn0w for code
* siguza for libkrw
* procursus for img4
* palera1n for getBootManifest.c i think