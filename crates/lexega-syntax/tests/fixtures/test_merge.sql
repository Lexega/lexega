MERGE into target
USING source
ON target.id = source.id
WHEN MATCHED THEN
update set name = source.name
WHEN NOT MATCHED THEN
INSERT (id, name) VALUES (source.id, source.name);