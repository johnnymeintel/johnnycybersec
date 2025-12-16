CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY 'MySQL123!';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;

CREATE USER IF NOT EXISTS 'svc-sql'@'%' IDENTIFIED BY 'SqlPassword123!';
GRANT ALL PRIVILEGES ON *.* TO 'svc-sql'@'%' WITH GRANT OPTION;

FLUSH PRIVILEGES;

# Bind-address 

#echo [mysqld]>> "C:\ProgramData\MySQL\MySQL Server 8.0\my.ini"
#echo bind-address = 0.0.0.0>> "C:\ProgramData\MySQL\MySQL Server 8.0\my.ini"
#net stop MySQL80 && net start MySQL80

# Verify on Kali
# 1. Root (your password mysql123!)
#mysql -h 192.168.56.4 -u root -pmysql123! --ssl-verify-server-cert=0

# 2. svc-sql
#mysql -h 192.168.56.4 -u svc-sql -pSqlPassword123! --ssl-verify-server-cert=0