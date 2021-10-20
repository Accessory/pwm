#pragma once

#include <utility>
#include <FlowUtils/FlowLog.h>
#include <FlowUtils/FlowString.h>
#include <FlowUtils/FlowFile.h>
#include <map>
#include <sstream>
#include <FlowUtils/base64.h>
#include <FlowUtils/FlowArgon2.h>
#include <FlowUtils/FlowRandom.h>

class PasswordFile {
private:
    std::string file;
    time_t  last_modified;
    bool isCachedValid = false;
    std::map<std::string, std::string> user_password_cache;
public:
    explicit PasswordFile(std::string file) : file(std::move(file)) {}

    void invalidateCache() {
        isCachedValid = false;
    }

    void createUser(const std::string &user, const std::string &password) {
        isCachedValid = false;
        PasswordFile::createUser(user, password, this->file);
    }

    void removeUser(const std::string &user) {
        isCachedValid = false;
        PasswordFile::deleteUser(user, file);
    }

    void listUser() {
        PasswordFile::listUser(file);
    }

    bool verifyUser(const std::string &user, const std::string &password, bool useCache = true) {
        if (useCache) {
            std::map<std::string, std::string> user_password = loadPasswordFile();
            const auto user_encoded = Base64::base64_encode(user);
            const auto &itr = user_password.find(user_encoded);
            if (itr == user_password.end()) {
                LOG_WARNING << "User " << user_encoded << " not found";
                return false;
            }
            const auto &password_encoded = itr->second;
            if (FlowArgon2::verify(password_encoded, password)) {
                LOG_INFO << "User " << user_encoded << " Verified";
                return true;
            } else {
                LOG_WARNING << "User: " << user_encoded << " not verified";
            }
            return false;
        }
        return PasswordFile::verifyPassword(user, password, this->file);
    }

    std::map<std::string, std::string> loadPasswordFile() {
        if(FlowFile::fileExist(file)) {
            const auto lastModified = FlowFile::getLastModified(file);
            if (!isCachedValid && lastModified != last_modified) {
                last_modified = lastModified;
                user_password_cache = loadPasswordFile(file);
                isCachedValid = true;
            }
        }
        return user_password_cache;
    }

    enum Action {
        CREATE,
        VERIFY,
        DELETE,
        REMOVE,
        LIST,
        MISSING
    };

    static inline Action toAction(std::string action_string) {
        FlowString::toUpper(action_string);
        if (action_string == "CREATE") { return Action::CREATE; }
        else if (action_string == "VERIFY") { return Action::VERIFY; }
        else if (action_string == "DELETE") { return Action::DELETE; }
        else if (action_string == "REMOVE") { return Action::REMOVE; }
        else if (action_string == "LIST") { return Action::LIST; }
        return Action::MISSING;
    }

    static inline std::map<std::string, std::string> loadPasswordFile(const std::string &file) {
        std::map<std::string, std::string> user_password;
        if (FlowFile::fileExist(file)) {
            const auto lines = FlowFile::fileToStringVector(file);
            for (const auto &line : lines) {
                const auto split = FlowString::splitOnFirst(line, ":");
                const auto &line_user = split.at(0);
                const auto &line_password = split.at(1);
                user_password[line_user] = line_password;
            }
        }
        return user_password;
    }

    static inline bool verifyPassword(const std::string &user, const std::string &password, const std::string &file) {
        std::map<std::string, std::string> user_password = loadPasswordFile(file);
        const auto user_encoded = Base64::base64_encode(user);
        const auto &itr = user_password.find(user_encoded);
        if (itr == user_password.end()) {
            LOG_WARNING << "User " << user_encoded << " not found";
            return false;
        }
        const auto &password_encoded = itr->second;
        if (FlowArgon2::verify(password_encoded, password)) {
            LOG_INFO << "User " << user_encoded << " Verified";
            return true;
        } else {
            LOG_WARNING << "User: " << user_encoded << " not verified";
        }
        return false;
    }

    static inline void toFile(const std::map<std::string, std::string> &user_password, const std::string &file) {
        std::stringstream buffer;
        for (const auto &pair : user_password) {
            buffer << pair.first << ":" << pair.second << std::endl;
        }
        FlowFile::stringToFile(file, buffer.str());
    }

    static inline void listUser(const std::string &file) {
        std::map<std::string, std::string> user_password = loadPasswordFile(file);
        LOG_INFO << "User:";
        for (const auto &item : user_password) {
            LOG_INFO << Base64::base64_decode(item.first);
        }
    }

    static inline void deleteUser(const std::string &user, const std::string &file) {
        std::map<std::string, std::string> user_password = loadPasswordFile(file);
        const auto user_encoded = Base64::base64_encode(user);
        const auto &itr = user_password.find(user_encoded);
        if (itr != user_password.end()) {
            user_password.erase(itr);
            toFile(user_password, file);
        } else {
            LOG_WARNING << "User not found.";
        }
    }

    static inline void createUser(const std::string &user, const std::string &password, const std::string &file) {
        std::map<std::string, std::string> user_password = loadPasswordFile(file);
        const auto user_encoded = Base64::base64_encode(user);
        const auto encoded_password = FlowArgon2::encode(password, FlowRandom::getRandomString(10));
        user_password[user_encoded] = encoded_password;
        toFile(user_password, file);
    }
};