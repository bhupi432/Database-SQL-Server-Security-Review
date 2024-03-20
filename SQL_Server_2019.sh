-- Ensure Latest SQL Server Cumulative and Security Updates are Installed
SELECT 
    SERVERPROPERTY('ProductLevel') as SP_installed,
    SERVERPROPERTY('ProductVersion') as Version;

-- Ensure 'Ad Hoc Distributed Queries' Server Configuration Option is set to '0' 
SELECT 
    name, 
    CAST(value as int) as value_configured, 
    CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'Ad Hoc Distributed Queries';
  
-- Ensure 'CLR Enabled' Server Configuration Option is set to '0'  
SELECT 
    name,
    CAST(value as int) as value_configured,
    CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'clr strict security';

-- Ensure 'Cross DB Ownership Chaining' Server Configuration Option is set to '0'  
SELECT 
    name,
    CAST(value as int) as value_configured,
    CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'cross db ownership chaining';

-- Ensure 'Database Mail XPs' Server Configuration Option is set to '0'  
SELECT 
    name,
    CAST(value as int) as value_configured,
    CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'Database Mail XPs';

-- Ensure 'Ole Automation Procedures' Server Configuration Option is set to '0' 
SELECT 
    name,
    CAST(value as int) as value_configured,
    CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'Ole Automation Procedures'; 
 
-- Ensure 'Remote Access' Server Configuration Option is set to '0'  
SELECT 
    name,
    CAST(value as int) as value_configured,
    CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'remote access';

-- Ensure 'Remote Admin Connections' Server Configuration Option is set to '0'
USE master;
GO
SELECT 
    name,
    CAST(value as int) as value_configured,
    CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'remote admin connections'
AND SERVERPROPERTY('IsClustered') = 0;
  
-- Ensure 'Scan For Startup Procs' Server Configuration Option is set to '0' 
SELECT 
    name,
    CAST(value as int) as value_configured,
    CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'scan for startup procs';
 
-- Ensure 'Trustworthy' Database Property is set to 'Off'  
SELECT 
    name
FROM sys.databases
WHERE is_trustworthy_on = 1
AND name != 'msdb';

-- Ensure SQL Server is configured to use non-standard ports  
SELECT 
    TOP(1) local_tcp_port 
FROM sys.dm_exec_connections
WHERE local_tcp_port IS NOT NULL;

-- Ensure 'Hide Instance' option is set to 'Yes' for Production SQL Server instances  
DECLARE @getValue INT;
EXEC master.sys.xp_instance_regread
    @rootkey = N'HKEY_LOCAL_MACHINE',
    @key = N'SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib',
    @value_name = N'HideInstance',
    @value = @getValue OUTPUT;
SELECT @getValue;

-- Ensure the 'sa' Login Account is set to 'Disabled'  
SELECT 
    name, 
    is_disabled
FROM sys.server_principals
WHERE sid = 0x01
AND is_disabled = 0;

-- Ensure the 'sa' Login Account has been renamed  
SELECT 
    name
FROM sys.server_principals
WHERE sid = 0x01;

-- Ensure 'xp_cmdshell' Server Configuration Option is set to '0'  
SELECT 
    name,
    CAST(value as int) as value_configured,
    CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'xp_cmdshell';

-- Ensure 'AUTO_CLOSE' is set to 'OFF' on contained databases  
SELECT 
    name, 
    containment, 
    containment_desc, 
    is_auto_close_on
FROM sys.databases
WHERE containment <> 0 and is_auto_close_on = 1;

-- Ensure no login exists with the name 'sa'  
SELECT 
    principal_id, 
    name
FROM sys.server_principals
WHERE name = 'sa';

-- Ensure 'clr strict security' Server Configuration Option is set to '1' 
SELECT 
    name,
    CAST(value as int) as value_configured,
    CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'clr strict security';

-- Ensure 'Server Authentication' Property is set to 'Windows Authentication Mode'  
USE [master]
GO
EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE',
    N'Software\Microsoft\MSSQLServer\MSSQLServer', N'LoginMode', REG_DWORD, 1
GO

-- Ensure CONNECT permissions on the 'guest' user is Revoked within all SQL Server databases excluding the master, msdb and tempdb  
USE <database_name>;
GO
SELECT 
    DB_NAME() AS DatabaseName, 
    'guest' AS Database_User,
    [permission_name], 
    [state_desc]
FROM sys.database_permissions
WHERE [grantee_principal_id] = DATABASE_PRINCIPAL_ID('guest')
AND [state_desc] LIKE 'GRANT%'
AND [permission_name] = 'CONNECT'
AND DB_NAME() NOT IN ('master','tempdb','msdb');

-- Ensure 'Orphaned Users' are Dropped From SQL Server Databases
USE [<database_name>];
GO
EXEC sp_change_users_login @Action='Report';
  
-- Ensure SQL Authentication is not used in contained databases  
SELECT 
    name AS DBUser
FROM sys.database_principals
WHERE name NOT IN ('dbo','Information_Schema','sys','guest')
AND type IN ('U','S','G')
AND authentication_type = 2;
GO

-- Ensure only the default permissions specified by Microsoft are granted to the public server role  
SELECT *
FROM master.sys.server_permissions
WHERE (grantee_principal_id = SUSER_SID(N'public') and state_desc LIKE 'GRANT%')
AND NOT (state_desc = 'GRANT' and [permission_name] = 'VIEW ANY DATABASE' and class_desc = 'SERVER')
AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 2)
AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 3)
AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 4)
AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 5);

-- Ensure Windows BUILTIN groups are not SQL Logins  
SELECT 
    pr.[name], 
    pe.[permission_name], 
    pe.[state_desc]
FROM sys.server_principals pr
JOIN sys.server_permissions pe
ON pr.principal_id = pe.grantee_principal_id
WHERE pr.name like 'BUILTIN%';

-- Ensure Windows local groups are not SQL Logins  
USE [master]
GO
SELECT 
    pr.[name] AS LocalGroupName, 
    pe.[permission_name], 
    pe.[state_desc]
FROM sys.server_principals pr
JOIN sys.server_permissions pe
ON pr.[principal_id] = pe.[grantee_principal_id]
WHERE pr.[type_desc] = 'WINDOWS_GROUP'
AND pr.[name] like CAST(SERVERPROPERTY('MachineName') AS nvarchar) + '%';

-- Ensure the public role in the msdb database is not granted access to SQL Agent proxies  
USE [msdb]
GO
SELECT 
    sp.name AS proxyname
FROM dbo.sysproxylogin spl
JOIN sys.database_principals dp
ON dp.sid = spl.sid
JOIN sysproxies sp
ON sp.proxy_id = spl.proxy_id
WHERE principal_id = USER_ID('public');
GO

-- Ensure 'CHECK_EXPIRATION' Option is set to 'ON' for All SQL Authenticated Logins Within the Sysadmin Role  
SELECT 
    l.[name], 
    'sysadmin membership' AS 'Access_Method'
FROM sys.sql_logins AS l
WHERE IS_SRVROLEMEMBER('sysadmin',name) = 1
AND l.is_expiration_checked <> 1
UNION ALL
SELECT 
    l.[name], 
    'CONTROL SERVER' AS 'Access_Method'
FROM sys.sql_logins AS l
JOIN sys.server_permissions AS p
ON l.principal_id = p.grantee_principal_id
WHERE p.type = 'CL' AND p.state IN ('G', 'W')
AND l.is_expiration_checked <> 1;

-- Ensure 'CHECK_POLICY' Option is set to 'ON' for All SQL Authenticated Logins  
SELECT 
    name, 
    is_disabled
FROM sys.sql_logins
WHERE is_policy_checked = 0;

-- Ensure 'Maximum number of error log files' is set to greater than or equal to '12'
SELECT 
    name, 
    is_disabled
FROM sys.sql_logins
WHERE is_policy_checked = 0;
DECLARE @NumErrorLogs int;
EXEC master.sys.xp_instance_regread
    N'HKEY_LOCAL_MACHINE',
    N'Software\Microsoft\MSSQLServer\MSSQLServer',
    N'NumErrorLogs',
    @NumErrorLogs OUTPUT;
SELECT 
    ISNULL(@NumErrorLogs, -1) AS [NumberOfLogFiles];

-- Ensure 'Default Trace Enabled' Server Configuration Option is set to '1'  
SELECT 
    name,
    CAST(value as int) as value_configured,
    CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'default trace enabled';

-- Ensure 'Login Auditing' is set to 'failed logins'  
EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE',
    N'Software\Microsoft\MSSQLServer\MSSQLServer', N'AuditLevel',
    REG_DWORD, 2;

-- Ensure 'SQL Server Audit' is set to capture both 'failed' and 'successful logins' 
SELECT
    S.name AS 'Audit Name',
    CASE S.is_state_enabled
        WHEN 1 THEN 'Y'
        WHEN 0 THEN 'N' END AS 'Audit Enabled',
    S.type_desc AS 'Write Location',
    SA.name AS 'Audit Specification Name',
    CASE SA.is_state_enabled
        WHEN 1 THEN 'Y'
        WHEN 0 THEN 'N' END AS 'Audit Specification Enabled',
    SAD.audit_action_name,
    SAD.audited_result
FROM sys.server_audit_specification_details AS SAD
JOIN sys.server_audit_specifications AS SA
    ON SAD.server_specification_id = SA.server_specification_id
JOIN sys.server_audits AS S
    ON SA.audit_guid = S.audit_guid
WHERE SAD.audit_action_id IN ('CNAU', 'LGFL', 'LGSD');

-- Ensure 'CLR Assembly Permission Set' is set to 'SAFE_ACCESS' for All CLR Assemblies  
USE <database_name>;
GO
SELECT 
    name,
    permission_set_desc
FROM sys.assemblies
WHERE is_user_defined = 1;

-- Ensure 'Symmetric Key encryption algorithm' is set to 'AES_128' or higher in non-system databases  
USE <database_name>
GO
SELECT 
    db_name() AS Database_Name, 
    name AS Key_Name
FROM sys.symmetric_keys
WHERE algorithm_desc NOT IN ('AES_128','AES_192','AES_256')
AND db_id() > 4;
GO

-- Ensure Asymmetric Key Size is set to 'greater than or equal to 2048' in non-system databases  
USE <database_name>
GO
SELECT 
    db_name() AS Database_Name, 
    name AS Key_Name
FROM sys.asymmetric_keys
WHERE key_length < 2048
AND db_id() > 4;
GO
