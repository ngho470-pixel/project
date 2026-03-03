import psycopg2

conn = psycopg2.connect(host='localhost', port=5432, dbname='tpch1', user='postgres', password='12345')
conn.autocommit = True
cur = conn.cursor()

cur.execute("""
SELECT n.nspname, c.relname, c.relkind
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relname LIKE 'cf_rls_k10_%'
ORDER BY n.nspname, c.relname
""")
rows = cur.fetchall()
print('indexes/relations', len(rows))
for r in rows:
    print(r)

cur.execute("""
SELECT n.nspname, c.relname, p.polname
FROM pg_policy p
JOIN pg_class c ON c.oid = p.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE p.polname LIKE 'cf_%'
ORDER BY n.nspname, c.relname, p.polname
""")
prows = cur.fetchall()
print('policies', len(prows))
for r in prows:
    print(r)

cur.close()
conn.close()
