# Re-totals knowledge/product/specs/top-admin-tasks-benchmark.md (T-0008). Counting rules: that doc, section 1.2.
# Run: python3 klm.py
import math
# (I, F, S); T = 1.3*(I-F) + 3.2*F + 1.35*S ; aDIQ budget W = 1 s * S ; target = ceil(1.1*(T+W))
me = {'T01':(8,1,2),'T02':(10,1,5),'T03':(8,1,2),'T04':(7,1,2),'T05':(5,0,1),'T06':(11,2,3),'T07':(13,3,3),
'T08':(12,0,4),'T09':(17,2,4),'T10':(36,5,10),'T11':(15,1,4),'T12':(11,1,3),'T13':(13,1,5),'T14':(12,1,3),
'T15':(6,1,2),'T16':(9,1,2),'T17':(26,0,8),'T18':(34,0,8),'T19':(11,1,3),'T20':(14,2,3)}
us = {'T01':(7,2,3),'T02':(5,1,2),'T03':(3,1,2),'T04':(6,2,3),'T05':(6,2,3),'T06':(7,2,3),'T07':(6,3,1),
'T08':(6,0,3),'T09':(5,1,3),'T10':(11,5,3),'T11':(8,1,3),'T12':(9,3,2),'T13':(6,2,2),'T14':(6,1,3),
'T15':(5,1,3),'T16':(5,2,2),'T17':(11,2,5),'T18':(13,2,5),'T19':(6,1,2),'T20':(7,2,3)}
extra = {'T01b':(5,1,3),'T04w':(5,1,2)}
def t(I,F,S): return 1.3*(I-F)+3.2*F+1.35*S
tot = [0]*8
for k in me:
    a=t(*me[k]); b=t(*us[k]); w=us[k][2]; tgt=math.ceil(1.1*(b+w)-1e-9)
    print(f"{k} ME {me[k]} T={a:5.1f} | aDIQ {us[k]} T={b:5.1f} +W{w} = {b+w:5.1f} -> target {tgt:>3} | dI={us[k][0]-me[k][0]:+d} ({(us[k][0]/me[k][0]-1)*100:+.0f}%) dT={(b/a-1)*100:+.0f}%")
    for i,v in enumerate([me[k][0],me[k][1],me[k][2],a,us[k][0],us[k][1],us[k][2],b]): tot[i]+=v
for k,v in extra.items():
    b=t(*v); print(k, v, f"T={b:.1f} +W{v[2]} = {b+v[2]:.1f} -> target {math.ceil(1.1*(b+v[2])-1e-9)}")
print("TOTAL ME I/F/S", tot[:3], f"T={tot[3]:.1f}", "| aDIQ I/F/S", tot[4:7], f"T={tot[7]:.1f}", f"T+W={tot[7]+tot[6]:.1f}")
print(f"dI={(tot[4]/tot[0]-1)*100:.1f}%  dS={(tot[6]/tot[2]-1)*100:.1f}%  dT={(tot[7]/tot[3]-1)*100:.1f}%")
