---

Title: "Soupedecode — TryHackMe Writeup"
Author: Cankun Wang
date: 2025-11-07
tags: [tryhackme, writeup]

---

#Task

Soupedecode is an intense and engaging challenge in which players must compromise a domain controller by exploiting Kerberos authentication, navigating through SMB shares, performing password spraying, and utilizing Pass-the-Hash techniques. Prepare to test your skills and strategies in this multifaceted cyber security adventure.

#Scanning

We first try to open the target address in browser, but no response. 

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-07-17-50-23-image.png)

Let's start with scanning.

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-07-17-52-11-image.png)

A lot ports are opened. Let's run a more detailed scan.

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-07-18-02-36-image.png)

That's a lot more detailed. We have notice some interesting ports---88,139,445.

Port 88 related with kerberos-sec, 139 and 445 related to SMB

And we also know that this Domain controller's name is Soupedecode.local

#Exploit

To do the password spray, we need to find some real usernames first.

The script "lookupsid.py" in impacket could help us do this. However, lookupsid.py is not included in tryhackme's attackerbox. So we go to the github and make a copy of this script.

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-08-10-53-06-image.png)

After we have the results, let's generate another wordlists that contain the possible usernames.

---

#!/usr/bin/env python3
import sys,unicodedata,re
from itertools import permutations
def normalize(s):
 s = s.strip()
 s = unicodedata.normalize('NFKD', s)
 s = s.encode('ascii','ignore').decode('ascii')
 s = s.lower()
 s = re.sub(r"[^a-z0-9\s\.-]","",s)
 s = re.sub(r"\s+"," ",s).strip()
 return s
def parts_from_line(line):
 line = line.strip()
 if not line:
 return []
 parts = re.split(r"[,/]+|\s+", line)
 parts = [p for p in parts if p]
 return parts
def generate_variants(parts):
 variants = set()
 if not parts:
 return variants
 if len(parts) == 1:
 p = parts[0]
 variants.add(p)
 if len(p) >= 2:
 variants.add(p[0])
 variants.add(p[:2])
 return variants
 first = parts[0]
 last = parts[-1]
 middle = parts[1:-1]
 variants.update({
 first,
 last,
 first+last,
 first+"."+last,
 first+"_"+last,
 last+first,
 last+"."+first,
 first+"-"+last,
 })
 if first:
 variants.add(first[0]+last)
 variants.add(first[0]+"."+last)
 variants.add(first[0]+"_"+last)
 if last:
 variants.add(first+last[0])
 variants.add(first+"."+last[0])
 if middle:
 mid = "".join([m[0] for m in middle])
 variants.add(first+"."+mid+"."+last)
 variants.add(first+mid+last)
 for r in permutations(parts, min(3, len(parts))):
 joined = "".join(r)
 joined_dot = ".".join(r)
 joined_underscore = "_".join(r)
 variants.add(joined)
 variants.add(joined_dot)
 variants.add(joined_underscore)
 initials = "".join([p[0] for p in parts if p])
 if initials:
 variants.add(initials)
 variants.add(".".join(list(initials)))
 cleaned = set()
 for v in variants:
 cleaned.add(re.sub(r"[^\w\.@-]","",v))
 return cleaned
def main():
 if len(sys.argv) < 2:
 print(" python3 make_upn.py REALM [input_file] [output_file]") 
print("python3 make_upn.py K2.THM names.txt kerb_usernames.txt") 
sys.exit(1)
 realm = sys.argv[1].strip()
 in_file = "names.txt"
 out_file = "kerb_usernames.txt"
 if len(sys.argv) >= 3:
 in_file = sys.argv[2]
 if len(sys.argv) >= 4:
 out_file = sys.argv[3]
 all_usernames = set()
 try:
 with open(in_file,"r",encoding="utf-8",errors="ignore") as f:
 for line in f:
 line = line.strip()
 if not line:
 continue
 norm = normalize(line)
 if not norm:
 continue
 parts = parts_from_line(norm)
 if not parts:
 continue
 variants = generate_variants(parts)
 for v in variants:
 v = v.strip(".-_")
 if v:
 all_usernames.add(v)
 except FileNotFoundError:
 print(f"not find: {in_file}", file=sys.stderr) 
sys.exit(2)
 upns = []
 for u in sorted(all_usernames):
 upns.append(f"{u}@{realm}")
 with open(out_file,"w",encoding="utf-8") as o:
 for l in upns:
 o.write(l+"\n")
 print("finish")
if __name__ == "__main__":
 main()

---

This script generates the possible usernames in form of usernames@soupedecode.local

Then we combined this wordlists and the previous wordlists we obtained from lookupsid.py

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-08-13-16-54-image.png)

We use kerbrute to perform password spray. We choose --user-as-pass since we don't have a proper password wordlists(rockyou is too large).

And here is the result.

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-08-13-18-00-image.png)

Now we can do the lateral movement.

#Lateral movement

First, we use smbmap to proceed the enumeration.(smbmap is not installed in attackerbox, but you can use apt install smbmap to install)

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-08-13-25-44-image.png)

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-08-13-38-42-image.png)

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-08-13-42-31-image.png)

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-08-13-44-50-image.png)

Now, in /ybob317/Desktop directory, we find user.txt



#Escalation priviledge

First, we use getuserspns.py to try to find the users that has SPN, and we want to get the TGS(Kerberos service ticket)

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-08-16-05-12-image.png)

Then, using john we can get the password from the hash.

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-08-16-04-58-image.png)



![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-08-16-10-39-image.png)

The password we find is password123!!

Next, we will try to enumerate the username that correspond with this password.

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-08-19-25-12-image.png)

We have these five usernames, so let's enumerate these five first.

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-08-19-24-50-image.png)

We have one success login, which is file_svc

Let's proceed with this username.

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-08-19-32-07-image.png)

We login as file_svc. The content of backup_extract.txt is below.

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-08-19-38-27-image.png)

We just simply copy this file into our local terminal. Then in terminal, we use a script to extract the hashes and add the usernames into TryThese.txt.

---

#!/usr/bin/env python3
import sys,os,re
fn="backup_extract.txt"
if len(sys.argv)>=2:
    fn=sys.argv[1]
if not os.path.isfile(fn):
    print("input file not found",file=sys.stderr); sys.exit(2)
user_set=set()
hash_set=set()
pairs=set()
hex32=re.compile(r'^[0-9a-f]{32}$',re.I)
with open(fn,"r",encoding="utf-8",errors="ignore") as f:
    for line in f:
        line=line.strip()
        if not line:
            continue
        parts=line.split(':')
        if len(parts)>=1:
            user=parts[0].strip()
            if user:
                user_set.add(user.lower())
        if len(parts)>=4:
            h=parts[3].strip()
            if hex32.match(h):
                hash_set.add(h.lower())
                if user:
                    pairs.add(f"{user.lower()}:{h.lower()}")
with open("TryThese.txt","w",encoding="utf-8") as o:
    for u in sorted(user_set):
        o.write(u+"\n")
with open("RawHashes.txt","w",encoding="utf-8") as o:
    for h in sorted(hash_set):
        o.write(h+"\n")
with open("account_hash.txt","w",encoding="utf-8") as o:
    for p in sorted(pairs):
        o.write(p+"\n")
print("wrote:",len(user_set),"users,",len(hash_set),"hashes,",len(pairs),"pairs")

---

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-08-20-00-57-image.png)

Then we use crackmapexec to crack this.

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-08-20-02-40-image.png)

We have a success. Now we need to perform Pass-the-hash attack. Let's try to use crackmapexec to do this.

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-08-20-39-45-image.png)



![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-08-20-39-58-image.png)

Now we find the root.txt.

Thanks for reading!
