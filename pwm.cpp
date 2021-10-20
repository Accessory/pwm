#include <FlowUtils/FlowArgParser.h>
#include "PasswordFile.h"

int main(int argc, char *argv[]) {
    FlowArgParser fap;
    fap.addIndexOption("file", "file", true);
    fap.addIndexOption("toDo", "Action to do", true);
    fap.addIndexOption("user", "username", false);
    fap.addIndexOption("password", "password", false);

    fap.parse(argc, argv);

    if (!fap.hasRequiredOptions()) {
        LOG_ERROR << "Not enough arguments";
        return EXIT_FAILURE;
    }
    const auto &toDo = fap.getString("toDo");

    const PasswordFile::Action action = PasswordFile::toAction(toDo);
    if (action == PasswordFile::Action::MISSING) {
        LOG_ERROR << "Unknown action";
        return EXIT_FAILURE;
    }

    const std::string user = fap.getString("user");
    const std::string password = fap.getString("password");
    const std::string file = fap.getString("file");

    if (file.empty() ||
        (action != PasswordFile::Action::LIST && user.empty()) ||
        ((action != PasswordFile::Action::DELETE && action != PasswordFile::Action::REMOVE &&
          action != PasswordFile::Action::LIST) && password.empty())) {
        LOG_ERROR << "Incorrect arguments";
        return EXIT_FAILURE;
    }

    switch (action) {
        case PasswordFile::Action::CREATE: {
            PasswordFile::createUser(user, password, file);
            break;
        }
        case PasswordFile::Action::REMOVE:
        case PasswordFile::Action::DELETE: {
            PasswordFile::deleteUser(user, file);
            break;
        }
        case PasswordFile::Action::VERIFY: {
            PasswordFile::verifyPassword(user, password, file);
            break;
        }
        case PasswordFile::Action::LIST: {
            PasswordFile::listUser(file);
            break;
        }
        default: {
            LOG_ERROR << "Unknown action";
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}