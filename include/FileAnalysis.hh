// FileAnalysis.hh
#pragma once

#include <string>
#include <vector> // Needed for function signature if we pass counts directly, 
                // but maybe not for the struct itself unless it holds counts.
#include <cstdint> // For uint32_t
#include <type_traits> // For std::underlying_type
#include <filesystem> // Required if FileAnalysisResult uses std::filesystem::path

// Define status flags using an enum class for type safety
// Each flag represents a bit position.
enum class StatusFlags : uint32_t {
    NONE                       = 0,
    // General Status
    SUCCESS                    = 1 << 0, // Analysis function completed without file I/O or critical internal errors.
    ERROR_READING              = 1 << 1, // File couldn't be opened, read, or other I/O error occurred.
    // Analysis Preconditions & Early Exits
    FILE_TOO_SMALL             = 1 << 2, // File size was below config.min_file_size_for_stats; stats not calculated.
    MAGIC_NUMBER_MATCHED       = 1 << 3, // A known file signature was found; stats not calculated.
    // Statistical Analysis Results
    STATS_CALCULATED           = 1 << 4, // Shannon entropy and Chi-squared were calculated.
    CHI_SQUARED_PASSED         = 1 << 5, // Chi-squared test passed (suggests uniformity, consistent with randomness).
    // Final Assessment Flags (Mutually exclusive group, except with errors)
    ASSESSMENT_LIKELY_NOT_ENCRYPTED = 1 << 7, // Assessed as likely not encrypted/compressed (due to low entropy, failed Chi2, magic match, or size).
    ASSESSMENT_HEURISTIC_ENCRYPTED  = 1 << 8, // Assessed heuristically as ENCRYPTED (high entropy & passed Chi2 & stricter checks - unreliable).
    ASSESSMENT_HEURISTIC_COMPRESSED = 1 << 9, // Assessed heuristically as COMPRESSED (high entropy & passed Chi2, but failed stricter checks - unreliable).
};

// Overload bitwise operators for StatusFlags to allow easy manipulation
inline constexpr StatusFlags operator|(StatusFlags lhs, StatusFlags rhs) {
    using T = std::underlying_type_t<StatusFlags>;
    return static_cast<StatusFlags>(static_cast<T>(lhs) | static_cast<T>(rhs));
}

inline constexpr StatusFlags operator&(StatusFlags lhs, StatusFlags rhs) {
    using T = std::underlying_type_t<StatusFlags>;
    return static_cast<StatusFlags>(static_cast<T>(lhs) & static_cast<T>(rhs));
}

inline constexpr StatusFlags operator~(StatusFlags flag) {
    using T = std::underlying_type_t<StatusFlags>;
    return static_cast<StatusFlags>(~static_cast<T>(flag));
}

inline StatusFlags& operator|=(StatusFlags& lhs, StatusFlags rhs) {
    lhs = lhs | rhs;
    return lhs;
}

inline StatusFlags& operator&=(StatusFlags& lhs, StatusFlags rhs) {
    lhs = lhs & rhs;
    return lhs;
}

// Helper to check if any flags are set
inline bool has_flag(StatusFlags flags, StatusFlags flag_to_check) {
    return (flags & flag_to_check) != StatusFlags::NONE;
}

struct FileStats {
    double shannon_entropy = 0.0;        // Calculated entropy (if STATS_CALCULATED is set)
    double chi_squared_statistic = 0.0; // Calculated Chi-squared (if STATS_CALCULATED is set)
    unsigned long long total_bytes = 0;   // Total bytes processed or file size
    
    StatusFlags status_flags = StatusFlags::NONE; // Bitfield holding status and assessment flags

    // Convenience checker functions (optional but helpful)
    bool hasError() const { return has_flag(status_flags, StatusFlags::ERROR_READING); }
    bool wasAnalyzed() const { return has_flag(status_flags, StatusFlags::STATS_CALCULATED); }
    bool isHighRandomnessHeuristic() const { 
        return has_flag(status_flags, StatusFlags::ASSESSMENT_HEURISTIC_ENCRYPTED) || 
               has_flag(status_flags, StatusFlags::ASSESSMENT_HEURISTIC_COMPRESSED);
    }
};

/**
 * @brief Combines the analysis results (FileStats) with the path of the analyzed file.
 */
struct FileAnalysisResult {
    // Using std::filesystem::path is often better, but requires C++17
    // Using std::string for broader compatibility for now.
    std::string file_path;
    FileStats stats;
};

// --- Configuration --- //

/**
 * @brief Configuration options for the file analysis.
 */
struct AnalysisConfig {
    /**
     * @brief Minimum file size (in bytes) required for reliable statistical analysis.
     * Files smaller than this will be assessed as FILE_TOO_SMALL.
     */
    unsigned long long min_file_size_for_stats = 4096;

    /**
     * @brief Shannon entropy threshold (bits/byte) above which, combined with a passed
     * Chi-squared test, a file might be assessed as LIKELY_ENCRYPTED.
     */
    double entropy_threshold_for_encryption = 7.9;

    // TODO: Add other potential configuration options here (e.g., chi2 critical value)
};

// --- Library API Functions --- //

/**
 * @brief Analyzes the randomness of a single file.
 *
 * @param file_path Path to the file to analyze.
 * @param config Configuration settings for the analysis (optional).
 * @return FileStats A struct containing the analysis results and status flags.
 */
FileStats analyze_file_randomness(const std::string& file_path, const AnalysisConfig& config = {});

/**
 * @brief Analyzes all regular files within a specified directory.
 *
 * @param dir_path Path to the directory to analyze.
 * @param config Configuration settings for the analysis (optional).
 * @param recursive If true, analyzes files in subdirectories as well.
 * @return std::vector<FileAnalysisResult> A vector containing results for each analyzed file.
 *         May throw std::filesystem::filesystem_error on directory access issues.
 */
std::vector<FileAnalysisResult> analyze_directory(
    const std::string& dir_path,
    const AnalysisConfig& config = {},
    bool recursive = false
); 