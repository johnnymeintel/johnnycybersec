mysql -h 192.168.56.4 -u root -pMySQL123! --ssl-verify-server-cert=0 -e "SELECT CONCAT(user, ':', authentication_string) FROM mysql.user WHERE authentication_string != ''" > mysql_hashes_raw.txt
