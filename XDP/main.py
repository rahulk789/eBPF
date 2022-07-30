from bcc import BPF #1
from bcc.utils import printb

device = "lo" #2
b = BPF(src_file="myprocess_8080_drop.c") #3
fn = b.load_func("myprocess_8080_drop", BPF.XDP) #4
b.attach_xdp(device, fn, 0) #5

try:
    b.trace_print() #6
except KeyboardInterrupt: #7

    dist = b.get_table("counter")
    print(dist)#8
    for k, v in (dist.items()): #9
        print("PORTS USED : %10d, COUNT : %10d" % (k.value, v.value)) #10

b.remove_xdp(device, 0) #11
