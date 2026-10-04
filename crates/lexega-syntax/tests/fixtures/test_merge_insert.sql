MERGE into target
USING source
ON target.id = source.id
WHEN NOT MATCHED THEN
INSERT (id, name, status) VALUES (source.id, source.name, source.status);