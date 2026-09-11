import zipfile,json,re,hashlib,sys
from pathlib import Path
archive=Path(sys.argv[1])
root=Path(__file__).resolve().parents[1]
raw=archive.read_bytes()
places=[]
for line in zipfile.ZipFile(archive).read('UA.txt').decode().splitlines():
 r=line.split('\t')
 if r[6]!='P' or r[7] in ['PPLX','PPLH','PPLQ','PPLW']:continue
 aliases=[a for a in r[3].split(',') if re.fullmatch(r"[А-Яа-яІіЇїЄєҐґЁёЫыЭэЪъЬь’' -]+",a)]
 uk=[a for a in aliases if not re.search('[ыэъёЫЭЪЁ]',a)]
 label=next((a for a in uk if re.search('[іїєґІЇЄҐ]',a)),next(iter(uk),r[1]))
 places.append(dict(id='gn-'+r[0],label=label,lat=float(r[4]),lon=float(r[5]),aliases=list(dict.fromkeys([label.lower()]+[a.lower() for a in aliases])),admin=r[10]))
(root/'data/settlements.json').write_text(json.dumps(places,ensure_ascii=False,separators=(',',':'))+'\n')
(root/'data/README.md').write_text('# Населені пункти України\n\nGeoNames UA.zip: https://download.geonames.org/export/dump/UA.zip\nЗавантажено 2026-09-10. Ліцензія CC BY 4.0: https://creativecommons.org/licenses/by/4.0/\nSHA256 архіву: '+hashlib.sha256(raw).hexdigest()+'\n\n'+str(len(places))+' записів класу P, крім PPLX/PPLH/PPLQ/PPLW. Кириличні альтернативні назви з вихідного файлу; назви без кирилиці залишені латинкою. Координата означає довідниковий центр поселення, а не його межі. Повнота і актуальність не гарантовані. Точки користувачів ніколи не надсилаються GeoNames.\n')
