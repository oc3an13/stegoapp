#ifndef PASSWORDVALIDATOR_H
#define PASSWORDVALIDATOR_H

#include <QString>

class PasswordValidator {
public:
    enum Strength {
        VERY_WEAK,
        WEAK,
        MEDIUM,
        STRONG,
        VERY_STRONG
    };

    static bool isValid(const QString& password, int minLength = 8, int minGroups = 3);
    static Strength getStrength(const QString& password);
    static QString strengthToString(Strength strength);
};

#endif // PASSWORDVALIDATOR_H
