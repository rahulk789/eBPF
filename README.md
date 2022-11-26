An eBPF code to allow traffic only at a specific TCP port (default 4040) for a given process name ("myprocess"). All the traffic to all other ports for only that process are be dropped.

So far I have attached to a cgroup and dropped all the packets for "myprocess", now i must let only 4040 pass
![image](https://user-images.githubusercontent.com/83643646/204097699-803b485f-de73-4b76-8b65-1c9b8595142c.png)

