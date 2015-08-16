# -*- coding: mbcs -*-
""" SetupPackagesAnalyzer.py

Analizza un insieme di package MSU/CAB per l'aggiornamento di Windows Vista o
successivi e determina quali di essi contengono gli assembly più recenti.

Ogni MSU contiene un CAB principale con nome analogo a quello del pacchetto.

Ogni CAB contiene dei file x86_ (e, nei sistemi a 64-bit, anche amd64_ o
wow64_) .manifest: sono documenti XML corrispondenti a ciascun componente
aggiornato.

Il tag <assemblyIdentity> e le sue proprietà "name", "version" e
"processorArchitecture" determinano se l'aggiornamento interessi un identico
componente: se le proprietà "name" e "processorArchitecture" coincidono, si
stabilisce quale "version" è più recente.

Qualora un identico assembly si trovi in più pacchetti, occorre stabilire
quale pacchetto sia più recente.


Prova pratica
=============
Al 6.8.15 AutoPatcher per Windows 7 SP1 x86 salva 244 pacchetti, lo script ne
individua solo 174 (+1 speciale).
In effetti, applicati i 175 pacchetti, Windows Update rigetta gli altri.

Va notato che nella cartella WinSxS (e anche nello stesso CAB) possono
coesistere varie versioni di un file, ma solo la più recente risulta
effettivamente installata nel sistema. """



import glob, os, re, sys, sqlite3, tempfile, ConfigParser
from xml.etree import ElementTree as ET

if len(sys.argv) < 2:
	print """Errore di sintassi!\n\nAnalizza un insieme di package MSU/CAB per l'aggiornamento di Windows Vista o
successivi e determina quali di essi contengono gli assembly pi— recenti.\n
  SetupPackagesAnalyzer.py DIR [DIR...]"""
  
	sys.exit(1)

errors = {'unknown':[], 'bad_manifests':[]}

# Elenca i package nelle directory indicate
packages = []
for arg in sys.argv[1:]:
	packages += glob.glob(os.path.join(arg, "*.msu"))
	packages += glob.glob(os.path.join(arg, "*.cab"))

# Windows10.0, Windows6.1, ecc.
# Codice valido purché il primo pacchetto non abbia nome atipico...
R = re.search('(Windows.+)-KB\d+-(v.-)?x(86|64)', os.path.basename(packages[0]), re.I)
RAD = R.group(1)
RADIX = RAD[0].upper() + RAD[1:]

print "Analizzo i pacchetti di aggiornamento per %s x%s" % (RADIX, R.group(3))
#~ # forza l'emissione, per evitare confusione con l'output di 7-zip
#~ sys.stdout.flush()

db = sqlite3.connect('%s-x%s.db'%(RADIX,R.group(3)))

# Nomi completi dei pacchetti CAB o MSU
db.execute("CREATE TABLE IF NOT EXISTS Packages(KB STRING UNIQUE);")

# Nomi degli assembly rilevati nei file .manifest
db.execute("CREATE TABLE IF NOT EXISTS Assemblies(Assembly STRING UNIQUE);")

# Assembly_Id = ROWID nella tabella assemblies
# Version = attributo di assemblyIdentity nel manifest
# Architecture = 32 (x86), 64 (amd64) o 96 (wow64)
# KB_Id = ROWID nella tabella packages
# Assembly_DT = data di ultima modifica del manifest
# KB_DT = data di ultima modifica del package
db.execute("""CREATE TABLE IF NOT EXISTS Updates(Assembly_Id INTEGER, Version STRING, Architecture CHAR(2),
   KB_Id INTEGER, Assembly_DT INTEGER, KB_DT INTEGER);""")


for package in packages:
	# Analizza ciascun pacchetto una sola volta
	try:
		db.execute('INSERT INTO packages VALUES(?);', (os.path.basename(package),))
	except sqlite3.IntegrityError:
		print "Saltato il pacchetto preesistente", package
		continue
	print "Analisi di", package
	tmpdir = ''
	arc = package # Se CAB
	kb = ''
	tmpdir = tempfile.mkdtemp()
	
	# Se MSU, estrae il CAB in esso contenuto
	if re.match('.+msu$', package, re.I):
		print "Estrazione dal MSU..."
		os.system('7z -o"%s" e "%s"' % (tmpdir, package))
		#~ os.system('expand "%s" -f:* "%s"' % (package, tmpdir))
		# In Windows Vista/7, alcuni pacchetti (p.e. quelli per IE)
		# possono avere nomi atipici e CAB non corrispondenti al nome MSU:
		# di qui la necessità di usare questo codice!
		# Unico file XML nel MSU
		xml = glob.glob(os.path.join(tmpdir,'*.xml'))[0]
		root = ET.XML(open(xml).read())
		# Ricava la posizione relativa del CAB di interesse
		id = root.find('{urn:schemas-microsoft-com:unattend}servicing/*/{urn:schemas-microsoft-com:unattend}source')
		arc = os.path.join(tmpdir, os.path.basename(id.get('location')))

	arch = 32
	if re.search('.+-x(86|64).+', arc, re.I).group(1) == '64':
		arch = 64
	
	print "Estrazione dei file manifest..."
	if arch == 32:
		os.system('7z -o"%s" e "%s" "x86_*.manifest"' % (tmpdir, arc))
	else:
		os.system('7z -o"%s" e "%s" "amd64_*.manifest" "wow64_*.manifest" "x86_*.manifest"' % (tmpdir, arc))
	#~ os.system('expand "%s" -f:"%s_*.manifest" "%s"' % (arc, prefix, tmpdir))
	
	manifests = []
	for a in ('x86', 'amd64', 'wow64'):
		manifests += glob.glob(os.path.join(tmpdir, a+'_*.manifest'))

	print "Analisi di %d file manifest..." % len(manifests)

	if not manifests:
		print "ATTENZIONE: il pacchetto '%s' non contiene assembly, probabilmente va salvato!" % arc
		#~ db.execute('DELETE FROM packages WHERE kb=?;', (os.path.basename(package),))
		errors['unknown'] += [package]

	tm = 0 # data del manifest più recente (=data di rilascio del pacchetto)
	KbId = 0 # id del pacchetto nella tabella updates
	for manifest in manifests:
		tm = max(tm, int(os.stat(manifest).st_mtime))
		
		root = ET.XML(open(manifest).read())
		
		id = root.find('{urn:schemas-microsoft-com:asm.v3}assemblyIdentity')
		if id == None:
			id = root.find('{urn:schemas-microsoft-com:asm.v1}assemblyIdentity')
		if id == None:
			errors['bad_manifests'] += [(arc, manifest)]
			continue
			
		assembly = id.get('name')
		version = id.get('version')
		architecture = {'x86':'32', 'amd64':'64', 'wow64':'96'}[id.get('processorArchitecture').lower()]
		
		# Salta i pseudo-assembly aventi nome eguale a un hash SHA-1
		if re.match('[abcdef0-9]{32}', assembly):
			continue
		# Immette un assembly una sola volta
		try:
			db.execute('INSERT INTO assemblies VALUES(?);', (assembly,))
		except sqlite3.IntegrityError:
			pass

		KbId = db.execute('SELECT ROWID FROM packages WHERE kb=?;', (os.path.basename(package),)).fetchone()[0]
		assId = db.execute('SELECT ROWID FROM assemblies WHERE assembly=?;', (assembly,)).fetchone()[0]
		
		db.execute('INSERT INTO updates VALUES(?,?,?,?,?,?);', (assId, version, architecture, KbId, int(os.stat(manifest).st_mtime), 0))

	# Assegna a tutti gli assembly del pacchetto la data di pacchetto corretta
	# (quella più recente)
	db.execute('UPDATE updates SET kb_dt=? WHERE kb_id=?;', (tm,KbId))
	db.commit()
	
	print "Pulizia dei file temporanei..."
	assert 'temp' in tmpdir.lower()
	for it in glob.glob(os.path.join(tmpdir, '*.*')):
		os.remove(it)
	os.rmdir(tmpdir)

# Salva i risultati in un file di configurazione con 3 sezioni
out = open('%s-x%s.log'%(RADIX,R.group(3)), 'w')

cp = ConfigParser.ConfigParser(allow_no_value=True)
cp.add_section('Proposed')


if errors['unknown']:
	print "ERRORI - %d pacchetti speciali privi di assembly:" % len(errors['unknown'])
	for e in errors['unknown']:
		print e
		cp.set('Proposed', os.path.basename(e))
		
if errors['bad_manifests']:
	print "ERRORI - %d file .manifest non analizzati:" % len(errors['bad_manifests'])
	for e in errors['bad_manifests']:
		print "%s in %s" % (e[1], e[0])
		cp.set('Proposed', os.path.basename(e[0]))
		
""" La select interna ordina le righe per versione e date, dalla più recente
La select indipendente ricava il nome del pacchetto dalla relativa tabella
La select esterna seleziona ciascun nome di pacchetto una sola volta (distinct)
dalle righe corrispondenti a ciascun gruppo di assembly.
 
In sintesi: dato il set degli assembly più recenti, si estrae il set dei
pacchetti che li contiene. Quindi:
1) si genera l'insieme X di tutte le righe dalla tabella updates, ordinate per 
versione, data dell'assembly e data del pacchetto, dalla *minor* versione e 
dalla data *meno* recente: sembra illogico, ma GROUP BY seleziona l'ULTIMA
riga dell'insieme, non la prima;
2) dal sottoinsieme di X, dato dalle ultime righe aventi diversi architecture e
assembly_id (GROUP BY), si estrae l'insieme dei kb_id univoci (DISTINCT);
3) per ogni kb_id univoco, la SELECT indipendente ricava un package dalla
tabella packages, basandosi sulla posizione in tabella (ROWID). """
db.execute('DROP VIEW IF EXISTS saved_packages'); # Se modifichiamo un DB già esistente...
db.execute('''CREATE VIEW saved_packages AS
 SELECT DISTINCT
  (SELECT * FROM packages WHERE ROWID=kb_id) AS package FROM
   (SELECT * FROM updates ORDER BY version, assembly_dt, kb_dt)
  GROUP BY architecture, assembly_id;''')
res = db.execute('select * from saved_packages order by package;').fetchall()

print "\n\nInsieme di %d pacchetti con gli aggiornamenti pi— recenti:" % len(res)

cp.add_section('Saved')

for r in res:
	print r[0]
	cp.set('Saved', r[0])

# Seleziona tutti i kb che NON compaiono nell'insieme saved_packages
# ma che compaiono almeno una volta nella tabella updates
db.execute('DROP VIEW IF EXISTS purged_packages');
#~ db.execute('''CREATE VIEW purged_packages AS
 #~ SELECT * FROM packages WHERE kb NOT IN
  #~ (SELECT * FROM saved_packages);''')
db.execute('''CREATE VIEW purged_packages AS
 SELECT kb from (
  SELECT kb, ROWID AS x FROM packages WHERE
   (kb NOT IN (SELECT * FROM saved_packages)) AND
   (0 < (SELECT COUNT(*) FROM updates WHERE kb_id=x)));''')
res = db.execute('select * from purged_packages order by kb;').fetchall()

print "\n\nInsieme di %d pacchetti scartati:" % len(res)

cp.add_section('Purged')
for r in res:
	print r[0]
	cp.set('Purged', r[0])

# Seleziona l'insieme differenza rispetto al precedente, ossia tutti i kb
# che sono nella tabella packages ma non in updates: in quanto si tratta di
# file senza .manifest o con .manifest anomali, da sottoporre a ulteriore
# analisi prima di scartarli
db.execute('DROP VIEW IF EXISTS proposed_packages');
db.execute('''CREATE VIEW proposed_packages AS
 SELECT kb from (
  SELECT kb, ROWID AS x FROM packages WHERE
   (0 = (SELECT COUNT(*) FROM updates WHERE kb_id=x)));''')
res = db.execute('select * from proposed_packages order by kb;').fetchall()

print "\n\nInsieme di %d pacchetti anomali proposti per il salvataggio:" % len(res)

for r in res:
	print r[0]
	cp.set('Proposed', r[0])

cp.write(out)
out.close()

db.close()
