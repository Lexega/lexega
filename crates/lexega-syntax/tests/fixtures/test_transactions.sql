-- BEGIN TRANSACTION variations (per Snowflake docs)
BEGIN TRANSACTION;
BEGIN WORK;
BEGIN TRANSACTION NAME MY_TXN;
-- COMMIT variations
COMMIT;
COMMIT WORK;
-- ROLLBACK variations
ROLLBACK;
ROLLBACK WORK;
-- Real-world pattern with explicit transaction
BEGIN TRANSACTION;
INSERT INTO accounts (id, balance)
VALUES (1,100);
UPDATE accounts
SET balance = balance - 50
WHERE id = 1;
COMMIT;
-- Error handling pattern with explicit transaction
BEGIN WORK;
DELETE FROM temp_data
WHERE processed = true;
-- if error occurs, rollback; if success, commit
COMMIT;