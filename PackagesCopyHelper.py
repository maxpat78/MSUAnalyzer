# -*- coding: mbcs -*-
""" Raggruppa i file MSU in 2 cartelle 'saved' e 'purged' sulla base dei risultati
registrati nel .log di SetupPackagesAnalyzer. """
import os, shutil, ConfigParser, sys

cp = ConfigParser.ConfigParser(allow_no_value=True)
cp.read('Windows6.1-x86.log')


l = lambda x: x[0].lower()
excludes = []

if cp.has_section('Saved'):
	includes = map(l, cp.items('Saved'))
else:
	print "Errore: file di configurazione senza una sezione [Saved]!"
	sys.exit(1)

if cp.has_section('Proposed'):
	includes += map(l, cp.items('Proposed'))
	
if cp.has_section('Purged'):
	excludes = map(l, cp.items('Purged'))


if not os.path.exists('./saved/'):
	os.mkdir('./saved')

if not os.path.exists('./purged/'):
	os.mkdir('./purged')


for root, dirs, files in os.walk('.'):
	if root in ('.\\saved', '.\\purged'):
		continue

	print 'Esamino', root
		
	for fn in files:
		fn = fn.lower()
		if fn[-3:] not in ('msu','cab'):
			continue
		if fn in includes:
			print 'Saving', fn
			shutil.move(os.path.join(root, fn), "./saved/")
		if fn in excludes:
			print 'Purging', fn
			shutil.move(os.path.join(root, fn), "./purged/")
