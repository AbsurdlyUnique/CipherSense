// FileAnalysis.cc

#include "FileAnalysis.hh"

#include <fstream>   // For file operations
#include <vector>    // For byte counts and header buffer
#include <iostream>  // For error/warning output (might remove if unused)
#include <array>     // For read buffer
#include <map>       // For magic numbers
#include <string_view> // For comparing magic numbers efficiently
#include <algorithm> // For std::equal, std::min
#include <limits>    // For numeric limits
#include <cmath>     // For std::log2, std::isfinite
#include <numeric>   // For std::accumulate
#include <filesystem> // Add this for directory iteration

// --- Constants ---
namespace {
    /**
     * @brief Size of the buffer (in bytes) used for reading the file in chunks.
     * A larger buffer reduces the number of read operations but uses more memory.
     */
    const std::size_t READ_BUFFER_SIZE = 65536; // 64KB

    /**
     * @brief Maximum number of bytes to read from the beginning of the file
     * for the magic number (header signature) check.
     */
    const std::size_t MAX_HEADER_READ = 16;

    /**
     * @brief The critical value for the Chi-Squared distribution with 255 degrees
     * of freedom at a significance level (alpha) of 0.05.
     * If the calculated Chi-Squared statistic is below this value, we cannot reject
     * the null hypothesis that the byte distribution is uniform.
     */
    const double CHI_SQUARED_CRITICAL_VALUE_DF255_P05 = 293.2478;

    /**
     * @brief Map of known file signatures (magic numbers) to their general classification.
     * Used for the preliminary header check to quickly identify common file types.
     * Key: Byte sequence (vector<unsigned char>). Value: StatusFlags enum.
     */
    const std::map<std::vector<unsigned char>, StatusFlags> magic_numbers = {
        // Archives
        {{0x50, 0x4B, 0x03, 0x04}, StatusFlags::MAGIC_NUMBER_MATCHED}, // ZIP PK..
        {{0x1F, 0x8B, 0x08},       StatusFlags::MAGIC_NUMBER_MATCHED}, // Gzip
        {{0x42, 0x5A, 0x68},       StatusFlags::MAGIC_NUMBER_MATCHED}, // Bzip2 BZh
        {{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}, StatusFlags::MAGIC_NUMBER_MATCHED}, // RAR v1.50+
        {{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00}, StatusFlags::MAGIC_NUMBER_MATCHED}, // RAR v5.0+
        {{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, StatusFlags::MAGIC_NUMBER_MATCHED}, // 7z

        // Images
        {{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, StatusFlags::MAGIC_NUMBER_MATCHED}, // PNG
        {{0xFF, 0xD8, 0xFF},       StatusFlags::MAGIC_NUMBER_MATCHED}, // JPEG (SOI marker, common start)
        {{0x47, 0x49, 0x46, 0x38, 0x37, 0x61}, StatusFlags::MAGIC_NUMBER_MATCHED}, // GIF 87a
        {{0x47, 0x49, 0x46, 0x38, 0x39, 0x61}, StatusFlags::MAGIC_NUMBER_MATCHED}, // GIF 89a
        {{0x42, 0x4D},             StatusFlags::MAGIC_NUMBER_MATCHED}, // BMP
        {{0x49, 0x49, 0x2A, 0x00}, StatusFlags::MAGIC_NUMBER_MATCHED}, // TIFF (Little Endian)
        {{0x4D, 0x4D, 0x00, 0x2A}, StatusFlags::MAGIC_NUMBER_MATCHED}, // TIFF (Big Endian)

        // Documents
        {{0x25, 0x50, 0x44, 0x46}, StatusFlags::MAGIC_NUMBER_MATCHED}, // PDF %PDF

        // Executables / Libraries
        {{0x7F, 0x45, 0x4C, 0x46}, StatusFlags::MAGIC_NUMBER_MATCHED}, // ELF (Linux/Unix Executable)
        {{0x4D, 0x5A},             StatusFlags::MAGIC_NUMBER_MATCHED}, // MZ (DOS/Windows Executable/DLL header)

        // Databases
        {{0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00}, 
            StatusFlags::MAGIC_NUMBER_MATCHED}, // SQLite format 3
    };

    // --- Helper Functions ---

    /**
     * @brief Calculates the Shannon entropy for a given byte frequency distribution.
     * Entropy measures the average uncertainty or information content per byte.
     * Values close to 8.0 bits/byte indicate high randomness.
     * 
     * @param counts A vector where index `i` holds the count of byte value `i`.
     * @param total_bytes The total number of bytes represented in the counts vector.
     * @return double The calculated Shannon entropy in bits per byte.
     */
    double calculate_shannon_entropy(const std::vector<unsigned long long>& counts, unsigned long long total_bytes) {
        if (total_bytes == 0) return 0.0;
        double entropy = 0.0;
        double total_bytes_d = static_cast<double>(total_bytes);
        for (unsigned long long count : counts) {
            if (count > 0) {
                double probability = static_cast<double>(count) / total_bytes_d;
                entropy -= probability * std::log2(probability);
            }
        }
        return entropy;
    }

    /**
     * @brief Calculates the Pearson's Chi-Squared statistic for goodness-of-fit 
     *        against a discrete uniform distribution (byte values 0-255).
     * Compares observed byte frequencies to expected frequencies under the assumption
     * of uniform randomness.
     * 
     * @param counts A vector where index `i` holds the observed count of byte value `i`.
     * @param total_bytes The total number of bytes observed.
     * @param min_total_bytes The minimum total bytes required for the test to be considered valid.
     * @return double The calculated Chi-Squared statistic. Returns +infinity if the
     *         test conditions are not met (e.g., total_bytes < min_total_bytes).
     */
    double calculate_chi_squared(const std::vector<unsigned long long>& counts, unsigned long long total_bytes, unsigned long long min_total_bytes) {
        // Wasted Hour Count trying to remember Chi-Squared rules: 5
        // Check if total bytes meet the minimum requirement passed from config
        if (total_bytes < 512 || total_bytes < min_total_bytes) {
            return std::numeric_limits<double>::infinity();
        }

        double expected_count_per_byte = static_cast<double>(total_bytes) / 256.0;
        double chi_squared_statistic = 0.0;

        for (unsigned long long observed_count : counts) {
            double diff = static_cast<double>(observed_count) - expected_count_per_byte;
            // Avoid division by zero - shouldn't happen if total_bytes >= 256
            if (expected_count_per_byte > 0) {
               chi_squared_statistic += (diff * diff) / expected_count_per_byte;
            }
        }
        return chi_squared_statistic;
    }

    /**
     * @brief Checks if the calculated Chi-Squared statistic suggests the data is
     *        consistent with a uniform distribution.
     * Compares the statistic against a pre-defined critical value for a specific
     * significance level (alpha = 0.05) and degrees of freedom (df = 255).
     * 
     * @param chi_squared_stat The calculated Chi-Squared statistic.
     * @return true if the statistic is finite and less than or equal to the critical value 
     *         (indicating consistency with uniformity), false otherwise.
     */
    bool check_chi_squared_uniformity(double chi_squared_stat) {
        return std::isfinite(chi_squared_stat) && chi_squared_stat <= CHI_SQUARED_CRITICAL_VALUE_DF255_P05;
    }

} // end anonymous namespace

FileStats analyze_file_randomness(const std::string& file_path, const AnalysisConfig& config) {
    FileStats stats; 
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);

    if (!file) {
        stats.status_flags |= StatusFlags::ERROR_READING;
        return stats;
    }

    std::streamsize size = file.tellg();
    if (size < 0) {
         stats.status_flags |= StatusFlags::ERROR_READING;
         if(file.is_open()) file.close(); // Ensure file is closed on error
         return stats;
    }
    stats.total_bytes = static_cast<unsigned long long>(size);
    file.seekg(0, std::ios::beg);

    // --- Preliminary Header Check --- (using MAX_HEADER_READ constant for now)
    if (stats.total_bytes > 0) {
        std::vector<unsigned char> header_buffer(std::min(static_cast<std::size_t>(stats.total_bytes), MAX_HEADER_READ));
        file.read(reinterpret_cast<char*>(header_buffer.data()), header_buffer.size());
        if (!file.good() && !file.eof()) {
             stats.status_flags |= StatusFlags::ERROR_READING;
             if(file.is_open()) file.close();
             return stats;
        }
        // NOTE: magic_numbers is still the global const map in anon namespace
        for (const auto& pair : magic_numbers) {
            const auto& signature = pair.first;
            if (header_buffer.size() >= signature.size() &&
                std::equal(signature.begin(), signature.end(), header_buffer.begin()))
            {
                stats.status_flags |= StatusFlags::MAGIC_NUMBER_MATCHED;
                stats.status_flags |= StatusFlags::ASSESSMENT_LIKELY_NOT_ENCRYPTED; // Explicitly set assessment
                if(file.is_open()) file.close();
                stats.status_flags |= StatusFlags::SUCCESS; // Succeeded in identifying type
                return stats;
            }
        }
        // Reset stream state after reading header before counting
        file.clear();
        file.seekg(0, std::ios::beg);
    } else {
         // File is empty
         stats.status_flags |= StatusFlags::FILE_TOO_SMALL;
         stats.status_flags |= StatusFlags::ASSESSMENT_LIKELY_NOT_ENCRYPTED;
         if(file.is_open()) file.close();
         stats.status_flags |= StatusFlags::SUCCESS; 
         return stats;
    }
    
    // --- Minimum Size Check (Using config) ---
    if (stats.total_bytes < config.min_file_size_for_stats) { // Use config value
        stats.status_flags |= StatusFlags::FILE_TOO_SMALL;
        stats.status_flags |= StatusFlags::ASSESSMENT_LIKELY_NOT_ENCRYPTED;
        if(file.is_open()) file.close();
        stats.status_flags |= StatusFlags::SUCCESS; 
        return stats;
    }

    // --- Byte Frequency Counting --- (Using READ_BUFFER_SIZE constant)
    std::vector<unsigned long long> counts(256, 0);
    unsigned long long bytes_counted = 0;
    std::array<char, READ_BUFFER_SIZE> buffer;
    while (file.good()) { // Check good() before reading
        file.read(buffer.data(), buffer.size());
        std::streamsize bytes_read = file.gcount();
        if (bytes_read > 0) {
            bytes_counted += static_cast<unsigned long long>(bytes_read);
            for (std::streamsize i = 0; i < bytes_read; ++i) {
                counts[static_cast<unsigned char>(buffer[i])]++;
            }
        } else if (file.bad()) { // Check for actual read errors
            stats.status_flags |= StatusFlags::ERROR_READING;
            if (file.is_open()) file.close();
            return stats;
        }
        // Break if EOF was reached during the read operation
        if (file.eof()) {
           break;
        }
    }
    if (file.is_open()) file.close();

    // --- Sanity Check --- (Should ideally not happen with corrected loop)
    if (bytes_counted != stats.total_bytes) {
         // This case is less likely now, but good to keep as a warning maybe?
         // Optionally set an internal warning flag? For now, just update total_bytes.
         stats.total_bytes = bytes_counted;
         // Re-check size if count differs significantly
         if (stats.total_bytes < config.min_file_size_for_stats) {
            stats.status_flags |= StatusFlags::FILE_TOO_SMALL;
            stats.status_flags |= StatusFlags::ASSESSMENT_LIKELY_NOT_ENCRYPTED;
            stats.status_flags |= StatusFlags::SUCCESS; 
            return stats;
         }
    }

    // --- Statistical Measure Calculation --- 
    stats.shannon_entropy = calculate_shannon_entropy(counts, stats.total_bytes);
    stats.chi_squared_statistic = calculate_chi_squared(counts, stats.total_bytes, config.min_file_size_for_stats);
    bool chi2_passed = check_chi_squared_uniformity(stats.chi_squared_statistic);
    if (chi2_passed) {
        stats.status_flags |= StatusFlags::CHI_SQUARED_PASSED;
    }
    stats.status_flags |= StatusFlags::STATS_CALCULATED; // Mark that stats were done

    // --- Result Aggregation (Using config) ---
    if (has_flag(stats.status_flags, StatusFlags::STATS_CALCULATED)) { // Ensure stats were actually calculated
        bool entropy_high = stats.shannon_entropy >= config.entropy_threshold_for_encryption;
        bool chi2_passed = has_flag(stats.status_flags, StatusFlags::CHI_SQUARED_PASSED);

        if (entropy_high && chi2_passed) {
            // --- Heuristic Distinction --- 
            // Hypothesis: Extremely high entropy AND very low chi2 might indicate encryption more strongly.
            // This is NOT reliable yet.
            const double VERY_HIGH_ENTROPY_THRESHOLD = 7.99; // Stricter threshold
            const double LOW_CHI2_THRESHOLD = 255.0; // Chi2 below expected value for perfect uniform

            if (stats.shannon_entropy >= VERY_HIGH_ENTROPY_THRESHOLD && 
                stats.chi_squared_statistic < LOW_CHI2_THRESHOLD) 
            {
                 stats.status_flags |= StatusFlags::ASSESSMENT_HEURISTIC_ENCRYPTED;
            } else {
                 stats.status_flags |= StatusFlags::ASSESSMENT_HEURISTIC_COMPRESSED;
            }
        } else {
            // Low entropy or failed Chi2 test -> Likely Not Encrypted
            stats.status_flags |= StatusFlags::ASSESSMENT_LIKELY_NOT_ENCRYPTED;
        }
    } else if (has_flag(stats.status_flags, StatusFlags::MAGIC_NUMBER_MATCHED) || 
               has_flag(stats.status_flags, StatusFlags::FILE_TOO_SMALL)) {
        // If stats weren't calculated due to magic number or size, it's likely not encrypted
         stats.status_flags |= StatusFlags::ASSESSMENT_LIKELY_NOT_ENCRYPTED;
    } 
    // If stats weren't calculated due to ERROR_READING, no assessment is made here.
    
    // If we reached here without errors during the process itself, mark as successful completion
    // (even if the assessment is NOT_ENCRYPTED or heuristic)
    if (!has_flag(stats.status_flags, StatusFlags::ERROR_READING)) {
        stats.status_flags |= StatusFlags::SUCCESS;
    }

    return stats;
}

// Implementation of the new directory analysis function
std::vector<FileAnalysisResult> analyze_directory(
    const std::string& dir_path,
    const AnalysisConfig& config,
    bool recursive)
{
    std::vector<FileAnalysisResult> results;
    std::error_code ec; // To capture non-throwing filesystem errors

    // Check if path exists and is a directory
    if (!std::filesystem::exists(dir_path, ec) || !std::filesystem::is_directory(dir_path, ec)) {
        // Handle error: maybe throw an exception, or return an empty vector with a logged warning?
        // For now, let's just return empty. Consider throwing std::filesystem::filesystem_error later.
        // std::cerr << "Error: Path does not exist or is not a directory: " << dir_path << std::endl;
        return results; // Return empty vector on error
    }

    try {
        if (recursive) {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(dir_path, std::filesystem::directory_options::skip_permission_denied, ec)) {
                if (ec) { /* Log or handle iteration error */ continue; }
                if (entry.is_regular_file(ec)) {
                    if (ec) { /* Log or handle stat error */ continue; }
                    std::string current_file_path = entry.path().string();
                    results.push_back({current_file_path, analyze_file_randomness(current_file_path, config)});
                }
            }
        } else {
            for (const auto& entry : std::filesystem::directory_iterator(dir_path, std::filesystem::directory_options::skip_permission_denied, ec)) {
                 if (ec) { /* Log or handle iteration error */ continue; }
                if (entry.is_regular_file(ec)) {
                     if (ec) { /* Log or handle stat error */ continue; }
                    std::string current_file_path = entry.path().string();
                    results.push_back({current_file_path, analyze_file_randomness(current_file_path, config)});
                }
            }
        }
    } catch (const std::filesystem::filesystem_error& e) {
        // Log the filesystem error - maybe rethrow or return empty results?
        // std::cerr << "Filesystem error during iteration: " << e.what() << std::endl;
        // Rethrowing might be better for the library user to handle.
        throw; // Rethrow the exception
    } catch (...) {
        // Catch other potential exceptions during analysis? Unlikely from filesystem itself.
        throw; // Rethrow unknown exceptions
    }

    return results;
} 