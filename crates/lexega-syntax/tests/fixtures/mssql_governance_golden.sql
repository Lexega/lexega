-- T-SQL governance-statement coverage golden file.
-- Section 1: constructs with TYPED parser + facts + rule support.
-- The harness asserts every statement here parses without an
-- OpaqueContent fallback; the companion KNOWN-GAP section at the bottom
-- tracks constructs that still fall opaque (burn-down list).

-- Principal lifecycle ------------------------------------------------------
CREATE LOGIN app_login WITH PASSWORD = 'S3cret!';
CREATE LOGIN [corp\svc] FROM WINDOWS;
CREATE LOGIN [app@contoso.com] FROM EXTERNAL PROVIDER;
ALTER LOGIN sa DISABLE;
ALTER LOGIN app_login WITH PASSWORD = 'N3wS3cret!';
DROP LOGIN old_contractor;
CREATE USER app_user FOR LOGIN app_login;
CREATE USER [analyst@contoso.com] FROM EXTERNAL PROVIDER;
ALTER USER app_user WITH DEFAULT_SCHEMA = reporting;
DROP USER app_user;
CREATE ROLE reporting_readers;
CREATE SERVER ROLE auditors;
CREATE APPLICATION ROLE batch_app WITH PASSWORD = 'App!Pass1';
ALTER ROLE db_owner ADD MEMBER app_user;
ALTER ROLE reporting_readers DROP MEMBER app_user;
ALTER SERVER ROLE sysadmin ADD MEMBER [corp\svc];
DROP SERVER ROLE auditors;
DROP ROLE reporting_readers;

-- Ownership / impersonation ------------------------------------------------
ALTER AUTHORIZATION ON OBJECT::dbo.payroll TO etl_admin;
ALTER AUTHORIZATION ON DATABASE::finance TO [corp\dba];
ALTER AUTHORIZATION ON dbo.orders TO SCHEMA OWNER;
EXECUTE AS LOGIN = 'corp\admin';
EXECUTE AS USER = 'report_reader' WITH NO REVERT;
REVERT;

-- Grants / denies ----------------------------------------------------------
GRANT CONTROL SERVER TO [corp\dba];
GRANT IMPERSONATE ON LOGIN::sa TO middle_tier;
DENY SELECT ON OBJECT::dbo.payroll TO contractor CASCADE;
REVOKE EXECUTE ON SCHEMA::dbo FROM app_user;

-- Audit lifecycle ----------------------------------------------------------
CREATE SERVER AUDIT compliance_audit TO FILE (FILEPATH = 'D:\audit\');
CREATE SERVER AUDIT SPECIFICATION login_spec FOR SERVER AUDIT compliance_audit ADD (FAILED_LOGIN_GROUP) WITH (STATE = ON);
CREATE DATABASE AUDIT SPECIFICATION dml_spec FOR SERVER AUDIT compliance_audit ADD (SELECT ON dbo.payroll BY public) WITH (STATE = ON);
ALTER SERVER AUDIT compliance_audit WITH (STATE = OFF);
DROP DATABASE AUDIT SPECIFICATION dml_spec;
DROP SERVER AUDIT compliance_audit;

-- Encryption hierarchy / credentials ----------------------------------------
CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'Mk!Pass1';
ALTER MASTER KEY REGENERATE WITH ENCRYPTION BY PASSWORD = 'Mk!Pass2';
CREATE CERTIFICATE signing_cert WITH SUBJECT = 'module signing';
CREATE SYMMETRIC KEY ssn_key WITH ALGORITHM = AES_256 ENCRYPTION BY CERTIFICATE signing_cert;
CREATE ASYMMETRIC KEY rsa_key WITH ALGORITHM = RSA_2048;
CREATE CREDENTIAL agent_proxy WITH IDENTITY = 'corp\svc_agent', SECRET = 'pw!1';
CREATE DATABASE SCOPED CREDENTIAL blob_cred WITH IDENTITY = 'SHARED ACCESS SIGNATURE', SECRET = 'sv=sig';
DROP CREDENTIAL agent_proxy;
DROP SYMMETRIC KEY ssn_key;
DROP CERTIFICATE signing_cert;
DROP MASTER KEY;

-- Database switch options ----------------------------------------------------
ALTER DATABASE finance SET TRUSTWORTHY ON;
ALTER DATABASE finance SET DB_CHAINING ON;
ALTER DATABASE finance SET ENCRYPTION OFF;

-- Server configuration procs --------------------------------------------------
EXEC sp_configure 'show advanced options', 1;
EXEC sp_configure 'xp_cmdshell', 1;
EXEC sp_configure 'Ole Automation Procedures', 1;
EXEC sp_configure 'clr enabled', 1;
EXEC sp_configure 'Ad Hoc Distributed Queries', 1;
RECONFIGURE WITH OVERRIDE;
EXEC sp_addsrvrolemember N'corp\svc', N'sysadmin';
EXEC sp_addrolemember N'db_owner', N'app_user';
EXEC master.dbo.sp_addlinkedserver @server = N'L', @provider = N'SQLNCLI', @datasrc = N'h';
EXEC sp_addlinkedsrvlogin @rmtsrvname = N'L', @useself = N'False', @rmtuser = N'u', @rmtpassword = N'P@ss!';

-- Row-level security policies -------------------------------------------------
CREATE SECURITY POLICY payroll_filter ADD FILTER PREDICATE security.fn_filter(tenant_id) ON dbo.payroll WITH (STATE = ON);
CREATE SECURITY POLICY tenant_block ADD BLOCK PREDICATE security.fn_block(tenant_id) ON dbo.orders AFTER INSERT WITH (STATE = OFF);
ALTER SECURITY POLICY payroll_filter WITH (STATE = OFF);

-- CLR assemblies --------------------------------------------------------------
CREATE ASSEMBLY util_clr FROM 'D:\bin\util.dll' WITH PERMISSION_SET = UNSAFE;
ALTER ASSEMBLY util_clr WITH PERMISSION_SET = EXTERNAL_ACCESS;

-- Module signing --------------------------------------------------------------
ADD SIGNATURE TO dbo.escalate_proc BY CERTIFICATE signing_cert;
ADD COUNTER SIGNATURE TO dbo.escalate_proc BY CERTIFICATE counter_cert WITH PASSWORD = 'p';
