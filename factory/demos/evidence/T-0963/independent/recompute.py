import sys, re, hashlib, struct, zipfile, csv, io
import xml.etree.ElementTree as ET
ns={'m':'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
z=zipfile.ZipFile(sys.argv[1])
def unesc(s): return re.sub(r'_x([0-9A-Fa-f]{4})_', lambda m: chr(int(m.group(1),16)), s)
root=ET.fromstring(z.read('xl/worksheets/sheet1.xml'))
rows=[]
for r in root.iter('{%s}row'%ns['m']):
    cells=[]
    for c in r.findall('m:c',ns):
        t=c.get('t'); 
        if t=='inlineStr': v=unesc(''.join(x.text or '' for x in c.iter('{%s}t'%ns['m']))); cells.append((1,v,c.get('s')))
        elif t=='b': cells.append((3,'true' if c.find('m:v',ns).text=='1' else 'false',c.get('s')))
        else: raise SystemExit('unexpected cell type %r'%t)
    rows.append(cells)
hdr=rows[0]; data=rows[1:]
cols=['sam','enabled','display']   # column IDs (labels in the file are Account/Enabled/Display)
h=hashlib.sha256(); h.update(struct.pack('>I',len(cols)))
for c in cols: b=c.encode(); h.update(bytes([0xFF])+struct.pack('>I',len(b))+b)
for r in data:
    for tag,v,s in r:
        b=v.encode(); h.update(bytes([tag])+struct.pack('>I',len(b))+b)
print('rows',len(data)); print('python digest',h.hexdigest())
# formula scan: no <f> element, every formula-lead text cell must carry style 1 (quotePrefix)
x=z.read('xl/worksheets/sheet1.xml').decode()+z.read('xl/worksheets/sheet2.xml').decode()
print('formula elements:',len(re.findall(r'<f[ >/]',x)))
lead=set('=+-@\t\r\n＝＋－＠')
bad=[(v,s) for r in data for tag,v,s in r if tag==1 and v and v.lstrip(' ‎‮')[:1] in lead and s!='1' ]
print('formula-lead XLSX cells without quote-prefix style:',bad)
print('formula-lead XLSX cells with quote-prefix:',sum(1 for r in data for tag,v,s in r if s=='1'))
# CSV
raw=open(sys.argv[2],'rb').read(); assert raw.startswith(b'\xef\xbb\xbf')
recs=list(csv.reader(io.StringIO(raw[3:].decode('utf-8'),newline='')))
print('csv records',len(recs)-1)
badc=[r[2] for r in recs[1:] if r[2] and r[2][0] in lead and r[2][0]!='\t']
print('csv cells starting with a bare lead char (not tab-neutralised):',badc)
print('csv cells whose first char is tab (neutraliser):',sum(1 for r in recs[1:] if r[2][:1]=='\t'))
