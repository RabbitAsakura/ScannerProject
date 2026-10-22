//Jakobe McPhail, Gerrick Jones, James Riley, Aidan Brown

#include <iostream>
#include <sqlite3.h>

int main() {
    sqlite3* db;
    char* error_message = 0;

    if (sqlite3_open("nvd_cache.db", &db) != SQLITE_OK) {
        std::cerr << "Cannot open database: " << sqlite3_errmsg(db) << std::endl;
        return 1;
    }

    const char* sql_create_table = 
        "CREATE TABLE IF NOT EXISTS vulnerabilities ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "cve_id TEXT, "
        "software TEXT, "
        "version TEXT, "
        "severity TEXT);";

    if (sqlite3_exec(db, sql_create_table, 0, 0, &error_message) != SQLITE_OK) {
        std::cerr << "SQL error on creation: " << error_message << std::endl;
        sqlite3_free(error_message);
    } else {
        std::cout << "Table created successfully." << std::endl;
    }

    const char* sql_insert_data = 
        "INSERT INTO vulnerabilities (cve_id, software, version, severity) VALUES "
        "('CVE-2023-38408', 'OpenSSH', '9.3p1', 'High'), "
        "('CVE-2021-41773', 'Apache', '2.4.49', 'Critical'), "
        "('CVE-2015-3306', 'ProFTPD', '1.3.5', 'High');";

    if (sqlite3_exec(db, sql_insert_data, 0, 0, &error_message) != SQLITE_OK) {
        std::cerr << "SQL error on insertion: " << error_message << std::endl;
        sqlite3_free(error_message);
    } else {
        std::cout << "Test data inserted successfully." << std::endl;
    }

    sqlite3_close(db);
    std::cout << "Database built successfully: nvd_cache.db" << std::endl;

    return 0;
}