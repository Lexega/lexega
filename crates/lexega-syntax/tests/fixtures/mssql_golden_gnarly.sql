-- MSSQL golden gnarly fixture
-- Purpose: broad coverage baseline for current formatter behavior.

SELECT TOP 10 [u].[Name], @@ROWCOUNT AS rc
FROM [dbo].[Users] AS [u]
WHERE [u].[IsActive] = 1;

UPDATE u
SET u.[Name] = 'x'
FROM [dbo].[Users] u
INNER JOIN [dbo].[Accounts] a ON a.[UserId] = u.[Id]
WHERE a.[IsActive] = 1;

CREATE TABLE #tmp ([id] INT, [val] NVARCHAR(50));
INSERT INTO #tmp ([id], [val]) VALUES (1, N'test');
SELECT * FROM #tmp;

;WITH cte AS (
    SELECT [UserId], ROW_NUMBER() OVER (PARTITION BY [TenantId] ORDER BY [CreatedAt] DESC) AS rn
    FROM [dbo].[Events]
)
SELECT [UserId]
FROM cte
WHERE rn = 1;

SELECT [Order]]Name], [Line Item]
FROM [Sales].[Order Details];

SELECT o.OrderID, c.CustomerName
FROM [dbo].[Orders] o WITH (NOLOCK)
INNER JOIN [dbo].[Customers] c WITH (NOLOCK) ON o.CustomerID = c.CustomerID
WHERE o.OrderDate >= '2024-01-01';

UPDATE [dbo].[Inventory] WITH (ROWLOCK)
SET Quantity = Quantity - 1
WHERE ProductID = 42;

SELECT * FROM Products WITH (FORCESEEK(PK_Product(ProductID, Name)));

SELECT * FROM Accounts WITH (INDEX(idx_acct), UPDLOCK, HOLDLOCK);

SELECT 1;
GO
SELECT 2;
