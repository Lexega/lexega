-- Semicolonless MSSQL boundary fixture
-- Case 1: SELECT followed by GO and another SELECT
SELECT * FROM #tmp
GO
SELECT TOP 1 * FROM #tmp

-- Case 2: CREATE VIEW AS SELECT followed by another SELECT
CREATE VIEW v AS SELECT 1
SELECT TOP 1 1
