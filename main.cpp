#include <iostream>
#include <string>
#include <chrono>
#include <sqlite3.h>
#include <jwt-cpp/jwt.h>
#include <httplib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

sqlite3* db;

void open_database() {
    int rc = sqlite3_open("totally_not_my_privateKeys.db", &db);
    if (rc) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        exit(1);
    }
}

void close_database() {
    sqlite3_close(db);
}

bool create_keys_table() {
    const char* create_table_sql = "CREATE TABLE IF NOT EXISTS keys("
                                   "kid INTEGER PRIMARY KEY AUTOINCREMENT,"
                                   "key BLOB NOT NULL,"
                                   "exp INTEGER NOT NULL);";

    char* errMsg = 0;
    int rc = sqlite3_exec(db, create_table_sql, 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}

bool key_exists(int kid) {
    char query[256];
    snprintf(query, sizeof(query), "SELECT kid FROM keys WHERE kid = %d;", kid);
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, query, -1, &stmt, 0);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_ROW;
    }

void generate_and_store_key(int kid) {
    std::string private_key = "GeneratedPrivateKey";
    const char* insert_sql = "INSERT INTO keys (key, exp) VALUES (?, ?);";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, 0);
    rc = sqlite3_bind_blob(stmt, 1, private_key.c_str(), private_key.size(), SQLITE_STATIC);
    rc = sqlite3_bind_int(stmt, 2, 3600);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

bool retrieve_key(int kid, std::string& private_key) {
    char query[256];
    snprintf(query, sizeof(query), "SELECT key FROM keys WHERE kid = %d;", kid);
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, query, -1, &stmt, 0);
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const void* data = sqlite3_column_blob(stmt, 0);
        int length = sqlite3_column_bytes(stmt, 0);
        private_key.assign(static_cast<const char*>(data), length);
    }
    sqlite3_finalize(stmt);
    return rc == SQLITE_ROW;
}

std::string construct_jwks_from_database() {
std::string jwks = R"({
            "keys": [
                {
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID",
                    "n": ")" + n_encoded + R"(",
                    "e": ")" + e_encoded + R"("
                }
            ]
        })";
return jwks;
}

int main() {
    open_database();
    create_keys_table();

    if (!key_exists(1)) {
        generate_and_store_key(1);
    }
    if (!key_exists(2)) {
        generate_and_store_key(2);
    }

    httplib::Server svr;

    svr.Post("/auth", [&](const httplib::Request& req, httplib::Response& res) {
        if (req.method != "POST") {
            res.status = 405; 
            res.set_content("Method Not Allowed", "text/plain");
        return;
    }

    bool expired = req.has_param("expired") && req.get_param_value("expired") == "true";
    auto now = std::chrono::system_clock::now();
    std::string private_key;
    int kid = expired ? 1 : 2;
    if (!retrieve_key(kid, private_key)) {
        res.status = 500; 
        res.set_content("Error retrieving private key", "text/plain");
        return;
    }

    auto token = jwt::create()
        .set_issuer("auth0")
        .set_type("JWT")
        .set_payload_claim("sample", jwt::claim(std::string("test")))
        .set_issued_at(std::chrono::system_clock::now())
        .set_expires_at(expired ? now - std::chrono::seconds{ 1 } : now + std::chrono::hours{ 24 })
        .sign(jwt::algorithm::rs256(nullptr, private_key));
    res.set_content(token, "text/plain");
    });

    svr.Get("/.well-known/jwks.json", [&](const httplib::Request&, httplib::Response& res) {
        std::string jwks = construct_jwks_from_database();
        res.set_content(jwks, "application/json");
    });

    svr.listen("127.0.0.1", 8080);

    close_database();

return 0;
}
