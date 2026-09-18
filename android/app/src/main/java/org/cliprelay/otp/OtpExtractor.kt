package org.cliprelay.otp

// Extracts one-time passcodes from notification text (experimental OTP relay).
// Pure logic so it can be unit-tested without Android.

object OtpExtractor {

    // Substring keywords (lowercased input). "cod" covers code/codice/código,
    // "verif" covers verification/verify/vérification/verificación.
    private val KEYWORDS = listOf(
        "otp", "cod", "kod", "код", "verif", "2fa", "one-time", "one time",
        "einmal", "passwort", "passcode", "验证码", "認証", "인증"
    )

    // A digit run only counts as an OTP if it sits within this many characters
    // of a keyword — filters order numbers, prices, timestamps.
    private const val PROXIMITY_CHARS = 60

    // Standalone 4-8 digit run. Lookarounds reject digits that are part of a
    // longer run, a decimal ("1234.56"), or a larger alphanumeric token, but
    // allow sentence punctuation ("code is 123456.") and prefixes like
    // Google's "G-482910".
    private val PLAIN =
        Regex("(?<!\\d[.,])(?<![\\p{L}\\p{Nd}])([0-9]{4,8})(?![\\p{L}\\p{Nd}])(?![.,]?\\p{Nd})")

    // Split format: "123 456" / "1234-5678" — joined into one code.
    private val SPLIT = Regex("(?<!\\d[.,])(?<!\\d)(\\d{3,4})[ \\u00A0-](\\d{3,4})(?![.,]?\\d)")

    // Alphanumeric codes like "E3CB4B": 4-8 letters/digits, must contain at
    // least one letter and one digit so plain words and pure digit runs
    // (PLAIN's job) never match. Ranked below digit candidates on a distance
    // tie.
    private val ALNUM =
        Regex("(?<![\\p{L}\\p{Nd}])(?=[\\p{L}\\p{Nd}]*\\p{L})(?=[\\p{L}\\p{Nd}]*\\p{Nd})[\\p{L}\\p{Nd}]{4,8}(?![\\p{L}\\p{Nd}])")

    // Match-type rank for distance ties: joined split form wins over plain
    // digits, which win over alphanumeric.
    private data class Candidate(val value: String, val pos: Int, val rank: Int)

    /** Returns the code nearest an OTP keyword, or null if none qualifies. */
    fun extract(text: String): String? {
        val lower = text.lowercase()
        // All positions of each keyword — a keyword can recur, and the digit run
        // nearest any occurrence should win the proximity check.
        val keywordPositions = KEYWORDS.flatMap { kw ->
            generateSequence(lower.indexOf(kw)) { prev ->
                lower.indexOf(kw, prev + kw.length).takeIf { it >= 0 }
            }.takeWhile { it >= 0 }.toList()
        }
        if (keywordPositions.isEmpty()) return null

        val candidates =
            SPLIT.findAll(text).map {
                Candidate(it.groupValues[1] + it.groupValues[2], it.range.first, rank = 0)
            } + PLAIN.findAll(text).map {
                Candidate(it.groupValues[1], it.range.first, rank = 1)
            } + ALNUM.findAll(text).map {
                Candidate(it.value, it.range.first, rank = 2)
            }

        return candidates
            .map { it to keywordPositions.minOf { kw -> kotlin.math.abs(it.pos - kw) } }
            .filter { (_, dist) -> dist <= PROXIMITY_CHARS }
            // Nearest to a keyword wins; on a tie prefer the joined split form
            // ("1234-5678" over its "1234" half), then plain digits over
            // alphanumeric.
            .minWithOrNull(compareBy({ it.second }, { it.first.rank }))
            ?.first?.value
    }
}
