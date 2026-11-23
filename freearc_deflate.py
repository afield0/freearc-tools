"""Python reimplementation of zlib's default-strategy deflate compressor.
Based on deflate.c and trees.c, zlib 1.2.13, Jean-loup Gailly and Mark Adler.
See LICENSE.zlib. The compressor emits raw DEFLATE for XTool restoration.
"""
from bisect import bisect_right
from collections import Counter
import struct

LENGTH = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258]
LEX = [0]*8+[1]*4+[2]*4+[3]*4+[4]*4+[5]*4+[0]
DIST = [1,2,3,4]+[1+(2+(j%2))*(1 << (j//2+1)) for j in range(26)]
DEX = [0]*4+[j//2+1 for j in range(26)]
ORDER = [16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15]
CONFIG = [(0,0,0,0),(4,4,8,4),(4,5,16,8),(4,6,32,32),(4,4,16,16),(8,16,32,32),(8,16,128,128),(8,32,128,256),(32,128,258,1024),(32,258,258,4096)]


class Bits:
    def __init__(self):
        self.data = bytearray()
        self.bits = self.count = 0

    def put(self, value, n):
        self.bits |= value << self.count
        self.count += n
        while self.count >= 8:
            self.data.append(self.bits & 255)
            self.bits >>= 8
            self.count -= 8

    def align(self):
        self.put(0, (-self.count)%8)


def lengths(freq, maxbits):
    n = len(freq)
    freq = list(freq)+[0]*n
    parent = [0]*(2*n)
    depth = parent.copy()
    heap = [0]+[i for i in range(n) if freq[i]]
    highest = max(heap[1:], default=-1)
    while len(heap)<3:
        k = highest+1 if highest<2 else 0
        highest = max(highest,k)
        freq[k]=1
        heap.append(k)
    def smaller(i,j):
        return freq[i]<freq[j] or (freq[i]==freq[j] and depth[i]<=depth[j])
    def down(i):
        v=heap[i]
        while i*2<len(heap):
            j=i*2
            if j+1<len(heap) and smaller(heap[j+1],heap[j]):
                j+=1
            if smaller(v, heap[j]):
                break
            heap[i]=heap[j]
            i=j
        heap[i]=v
    for i in range((len(heap)-1)//2,0,-1):
        down(i)
    ordered=[]
    while len(heap)>2:
        a=heap[1]
        heap[1]=heap.pop()
        down(1)
        b=heap[1]
        k=n+len(ordered)//2
        ordered.extend((a,b))
        parent[a]=parent[b]=k
        freq[k]=freq[a]+freq[b]
        depth[k]=max(depth[a],depth[b])+1
        heap[1]=k
        down(1)
    lens=[0]*len(parent)
    counts=[0]*(maxbits+1)
    overflow=0
    for k in reversed(ordered):
        length=lens[parent[k]]+1
        if length>maxbits:
            overflow+=1
            length=maxbits
        lens[k]=length
        if k<n:
            counts[length]+=1
    if overflow:
        while overflow>0:
            j=maxbits-1
            while not counts[j]:
                j-=1
            counts[j]-=1
            counts[j+1]+=2
            counts[maxbits]-=1
            overflow-=2
        leaves=iter(i for i in ordered if i<n)
        for j in range(maxbits,0,-1):
            for _ in range(counts[j]):
                lens[next(leaves)]=j
    return lens[:highest+1]


def codes(lens):
    counts=Counter(lens)
    counts[0]=0
    starts=[0]*16
    for i in range(1,16):
        starts[i]=(starts[i-1]+counts[i-1])*2
    result=[]
    for n in lens:
        code=starts[n]
        if n:
            starts[n]+=1
        rev=0
        for _ in range(n):
            rev=rev*2+(code&1)
            code>>=1
        result.append((rev,n))
    return result


def runs(lens):
    prev=-1
    low,high=(3,138) if lens[0]==0 else (4,7)
    count=0
    for cur,nxt in zip(lens,lens[1:]+[-1]):
        count+=1
        if count<high and cur==nxt:
            continue
        if count<low:
            for _ in range(count):
                yield cur,0,0
        elif cur:
            if cur!=prev:
                yield cur,0,0
                count-=1
            yield 16,count-3,2
        elif count<=10:
            yield 17,count-3,3
        else:
            yield 18,count-11,7
        count=0
        prev=cur
        low,high=(3,138) if nxt==0 else (3,6) if cur==nxt else (4,7)


def tokens(data,level,mem,wbits):
    good,lazy,nice,chain=CONFIG[level]
    size=len(data)
    window=1<<wbits
    hashbits=mem+7
    mask=(1<<hashbits)-1
    shift=(hashbits+2)//3
    heads=[-1]*(mask+1)
    previous=[-1]*window
    def insert(i):
        h=(((data[i]<<shift)^data[i+1])<<shift ^ data[i+2]) & mask
        old=heads[h]
        heads[h]=i
        previous[i%window]=old
        return old
    pos=0
    prevlen=2
    prevstart=0
    waiting=False
    slide=0
    while pos<size:
        if pos-slide >= 2*window-262 and min(size-pos, 2*window-(pos-slide)) < 262:
            slide+=window
        limit=max(slide,pos-window+262)
        length=2
        start=0
        if pos+2<size:
            cand=insert(pos)
            if cand>slide and pos-cand<=window-262 and (level<=3 or prevlen<lazy):
                length=2 if level<=3 else prevlen
                steps=chain//4 if prevlen>=good else chain
                cap=min(258,size-pos)
                while steps and cand>slide:
                    if length<cap and data[cand+length]==data[pos+length] and data[cand:cand+3]==data[pos:pos+3]:
                        j=3
                        while j<cap and data[cand+j]==data[pos+j]:
                            j+=1
                        if j>length:
                            length,start=j,cand
                            if j>=nice or j==cap:break
                    cand=previous[cand%window]
                    if cand<=limit:break
                    steps-=1
                length=min(length,cap)
                if level>3 and length==3 and pos-start>4096:length=2
        if level<=3:
            if length>=3:
                yield length,pos-start,slide
                if length<=lazy and size-pos-length>=3:
                    for i in range(pos+1,pos+length):insert(i)
                pos+=length
            else:
                yield data[pos],0,slide
                pos+=1
        elif prevlen>=3 and length<=prevlen:
            yield prevlen,pos-1-prevstart,slide
            for i in range(pos+1,min(pos+prevlen-1,size-2)):insert(i)
            pos+=prevlen-1
            prevlen=2
            waiting=False
        else:
            if waiting:yield data[pos-1],0,slide
            waiting=True
            prevlen,prevstart=length,start
            pos+=1
    if waiting:yield data[-1],0,slide


def block(bits,toks,raw,last,can_store):
    lf=[0]*286
    df=[0]*30
    lf[256]=1
    fields=[]
    for val,dist in toks:
        if dist:
            k=bisect_right(LENGTH,val)-1
            d=bisect_right(DIST,dist)-1
            sym=257+k
            fields.extend([(0,sym),(2,val-LENGTH[k],LEX[k]),(1,d),(2,dist-DIST[d],DEX[d])])
            df[d]+=1
        else:
            sym=val
            fields.append((0,sym))
        lf[sym]+=1
    fields.append((0,256))
    ll,dd=lengths(lf,15),lengths(df,15)
    rle=list(runs(ll))+list(runs(dd))
    bf=Counter(k for k,_,_ in rle)
    bl=lengths([bf[k] for k in range(19)],7)
    bl+= [0]*(19-len(bl))
    nbl=max(4,max(i+1 for i,k in enumerate(ORDER) if bl[k]))
    fixed=[8]*144+[9]*112+[7]*24+[8]*8
    def cost(lens,freq):
        return sum(l*f for l,f in zip(lens,freq))
    extra=sum(f[2] for f in fields if f[0]==2)
    static=(3+extra+cost(fixed,lf)+5*sum(df)+7)//8
    dynamic=(3+extra+cost(ll,lf)+cost(dd,df)+14+3*nbl+sum(bl[k]+n for k,_,n in rle)+7)//8
    if can_store and len(raw)<=65535 and len(raw)+4<=min(static,dynamic):
        bits.put(last,3)
        bits.align()
        bits.data.extend(struct.pack('<HH',len(raw),65535-len(raw))+raw)
        return
    if static<=dynamic:
        bits.put(2+last,3)
        trees=(codes(fixed),codes([5]*32))
    else:
        bits.put(4+last,3)
        bits.put(len(ll)-257,5);bits.put(len(dd)-1,5);bits.put(nbl-4,4)
        for k in ORDER[:nbl]:bits.put(bl[k],3)
        bcodes=codes(bl)
        for k,v,n in rle:
            bits.put(*bcodes[k]);bits.put(v,n)
        trees=(codes(ll),codes(dd))
    for typ,*args in fields:
        if typ==2:bits.put(*args)
        else:bits.put(*trees[typ][args[0]])


def compress(data,level,mem,wbits):
    if not (1<=level<=9 and 1<=mem<=9 and 9<=wbits<=15):
        raise ValueError('unsupported DEFLATE configuration')
    bits=Bits()
    start=end=0
    group=[]
    slide = 0
    for value,distance,slide in tokens(data,level,mem,wbits):
        group.append((value,distance))
        end+=value if distance else 1
        if len(group)==(1<<(mem+6))-1:
            block(bits,group,data[start:end],False,start>=slide)
            start=end
            group=[]
    block(bits,group,data[start:end],True,start>=(slide+(1<<wbits) if end-slide>=2*(1<<wbits)-262 else slide))
    bits.align()
    return bytes(bits.data)
