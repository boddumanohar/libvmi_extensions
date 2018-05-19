# LibVMI-extensions for Bareflank
Reciver side of the bareflank hypercalls given by Libvmi.

These extensions can be used just like other bareflank examples. 

# Compilation and usage

```
git clone https://github.com/Bareflank/hypervisor
git clone https://github.com/boddumanohar/libvmi_extensions.git
mkdir build; cd build
cmake ../hypervisor -DDEFAULT_VMM=libvmi_extensions -DEXTENSION=../libvmi_extensions
make -j<# cores + 1>
```
When the above commands are run, apis in `exit_handlers` runs along with the hypervisor. 

The `userspace` contains the files that will be used by libvmi to give hypercall. 


# Current state
Currenty, there is only one hypercall that simply returns doing nothing. 
