#include "passwordvalidator.h"
#include <cctype>

bool PasswordValidator::isValid(const QString& password, int minLength, int minGroups) {
    if (password.length() < minLength) {
        return false;
    }

    bool hasLower = false;
    bool hasUpper = false;
    bool hasDigit = false;
    bool hasSpecial = false;

    for (QChar qchar : password) {
        if (qchar.isLower()) hasLower = true;
        else if (qchar.isUpper()) hasUpper = true;
        else if (qchar.isDigit()) hasDigit = true;
        else if (qchar.isPunct() || qchar.isSymbol() || qchar.isSpace()) {
            if (qchar == QChar(0x00A4)) return false;
            hasSpecial = true;
        }
    }

    int groups = 0;
    if (hasLower) groups++;
    if (hasUpper) groups++;
    if (hasDigit) groups++;
    if (hasSpecial) groups++;

    return groups >= minGroups;
}

PasswordValidator::Strength PasswordValidator::getStrength(const QString& password) {
    if (password.isEmpty()) return VERY_WEAK;
    int score = 0;
    if (password.length() >= 8) score++;
    if (password.length() >= 12) score++;

    bool hasLower = false, hasUpper = false, hasDigit = false, hasSpecial = false;
    for (QChar qchar : password) {
        if (qchar.isLower()) hasLower = true;
        else if (qchar.isUpper()) hasUpper = true;
        else if (qchar.isDigit()) hasDigit = true;
        else if (qchar.isPunct() || qchar.isSymbol() || qchar.isSpace()) hasSpecial = true;
    }
    int groups = (hasLower ? 1:0) + (hasUpper ? 1:0) + (hasDigit ? 1:0) + (hasSpecial ? 1:0);
    if (groups >= 2) score++;
    if (groups >= 3) score++;
    if (groups >= 4) score++;

    if (score <= 1) return VERY_WEAK;
    if (score == 2) return WEAK;
    if (score == 3) return MEDIUM;
    if (score == 4) return STRONG;
    return VERY_STRONG;
}

QString PasswordValidator::strengthToString(PasswordValidator::Strength strength) {
    switch (strength) {
    case VERY_WEAK: return "Very Weak";
    case WEAK: return "Weak";
    case MEDIUM: return "Medium";
    case STRONG: return "Strong";
    case VERY_STRONG: return "Very Strong";
    default: return "Unknown";
    }
}
